"""The append-only trail on disk, and everything that has tried to break it.

Split out of `audit.py`. `InMemoryAuditSink` is thirty lines because keeping a bounded
window in memory is thirty lines of work. This is three hundred because a file is
shared, survives the process, and is the artifact somebody will be asked to trust in an
argument — so every one of its paragraphs is a defence against a specific way that went
wrong:

* a partial `os.write` leaving half a record, rolled back by `ftruncate`;
* two Gates in one process appending through separate handles;
* the same file reached by two spellings of its path;
* a log deleted and quietly restarted, which the chain alone cannot see;
* a record that parses to one thing and reads as another.

It is also **total**: an exception out of `record()` costs a completed call its result
without preventing anything, because it runs on the POST path after the side effect. The
one way it may raise is `strict`, which a host sets when a lost record is worse than a
failed call — and that flag is honoured through the Gate now, which took three findings.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import sys
import threading
import warnings
from pathlib import Path
from typing import Any

from histos.trail.logpath import (
    _PATH_HIGH_WATER,
    _PATH_LOCKS,
    _PATH_LOCKS_GUARD,
    _lock_key,
    _path_key,
    tip_path_for,
)
from histos.trail.verify import _chain_digest, _read_last_line, _tip_body, verify_chain

try:  # POSIX only; Windows gets in-process locking and nothing more (documented).
    import fcntl
except ImportError:  # pragma: no cover - exercised only on Windows
    fcntl = None  # type: ignore[assignment]


class JSONLAuditSink:
    """Append-only JSONL on the local filesystem. Optionally hash-chained.

    Lines are pure ASCII (``ensure_ascii=True``), so an ordinary
    ``open(path, encoding="utf-8")`` can read the whole file no matter what text a
    model put in an argument name; non-ASCII survives as a ``\\uXXXX`` escape that
    ``json.loads`` turns back into the original string.

    With ``hash_chain=True`` each record gains ``seq`` (its 1-based position in this
    file), ``prev`` (the previous record's hash) and ``hash`` (over its own canonical
    body, which includes ``seq`` and ``prev``).

    **Tamper-evidence, stated honestly:**

    * **Unkeyed** (``key=None``, default) the chain uses plain sha256. It detects
      reordering, deletion and naive single-record edits — but an attacker with
      write access to the file can rewrite a record and *recompute every
      downstream hash* (the algorithm is public), and :meth:`verify` then passes.
      So unkeyed = integrity against accident/careless edit, **not** against a
      motivated writer.
    * **Keyed** (pass ``key=<secret>`` kept off this machine) the chain uses
      HMAC-SHA256, so recomputation requires the secret and content rewriting is
      detectable. Use a key for real tamper-evidence.

    **Why there is a sidecar.** A forward-walking chain can only prove that what is
    *present* is in order. Deleting records off the *end* forges nothing — the
    shorter prefix is a valid chain — so a truncated log verified clean and an
    attacker's denied attempts were simply the last lines of the file. Detecting that
    needs one piece of state the log itself cannot hold, so every append also rewrites
    ``<log>.tip``: the record count, the tip hash, and a digest over both. Keyed, that
    digest is an HMAC the attacker cannot produce for a count they never saw; unkeyed
    it is accident-evident only, exactly like the chain.

    **Concurrency.** ``record`` is safe from several threads (``_lock``) and, on
    POSIX, from several processes (``flock`` on the log). The chain tip is re-read
    from the file inside that lock rather than cached, because a snapshot taken at
    construction is wrong the moment a second writer exists — and one honest
    concurrent append used to break the chain permanently, which taught operators to
    stop believing ``histos audit verify``.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        hash_chain: bool = True,
        key: bytes | None = None,
        mode: int = 0o600,
        strict: bool = False,
    ) -> None:
        if not isinstance(hash_chain, bool):
            raise ValueError(f"hash_chain must be true or false, got {hash_chain!r}")
        if key is not None and (not isinstance(key, bytes) or not key):
            raise ValueError("key must be non-empty bytes when supplied")
        if key is not None and not hash_chain:
            raise ValueError("key has no effect when hash_chain is false")
        if isinstance(mode, bool) or not isinstance(mode, int) or not 0 <= mode <= 0o7777:
            raise ValueError(f"mode must be an integer permission mask from 0o0000 to 0o7777, got {mode!r}")
        if not isinstance(strict, bool):
            raise ValueError(f"strict must be true or false, got {strict!r}")
        self.path = Path(path)
        self.tip_path = tip_path_for(self.path)
        self.hash_chain = hash_chain
        self._key = key
        # The highest `seq` this sink has written, and its hash. Deleting the log
        # together with its sidecar leaves nothing on disk to contradict a fresh chain,
        # so the next append would start at seq 1 with a correctly-MAC'd tip and
        # `verify_chain` would report OK — erasure that forges nothing and proves
        # nothing. Nothing left on disk can close that, but a live process remembers.
        #
        # What it does with that memory matters. Raising was the obvious move and the
        # wrong one: `record()` is called from `Gate._emit`, including on the POST path,
        # where the tool has already run — so an erasure timed mid-call destroyed a
        # completed call's result and handed the caller an exception instead. That is
        # precisely the failure this sink was fixed for one release earlier. So it does
        # not raise, and it does not lose the record either. It keeps numbering from
        # where it left off and points `prev` at the hash it remembers, which no line in
        # the truncated file matches — the break is written into the file itself, and
        # `verify_chain` and the tip sidecar both report it.
        #
        # Cross-restart erasure is a real residual and is documented as one: ship the tip
        # somewhere the host cannot write.

        # Owner-only by default. The trail records `identity` in the clear — that is
        # what makes it evidence — and the default umask created it 0644, so on any
        # shared host every local account could read who called what. Applied on
        # creation only, so an operator who has deliberately widened an existing file,
        # or pointed the sink at a group-writable collector directory, keeps their
        # choice. Pass `mode=` to create it differently.
        self._mode = mode

        # Records this sink could not write, for the same reason `InMemoryAuditSink`
        # counts what it drops: the loss is a fact about the evidence and has to be
        # legible. See `record()` for why it is a counter and not an exception.
        self.failed = 0
        # Off by default, because `record()` runs on the POST path after the tool has
        # already produced its side effect, and an exception there costs a completed
        # call its result without preventing anything. On, for a host whose evidence
        # requirement outranks availability — a regulated trail where a lost record is
        # worse than a failed call. Either way `failed` counts and the warning fires.
        #
        # Public, and read by `Gate._emit`. It used to be private, and the gate wrapped
        # `record()` in a blanket `except Exception` that caught the strict re-raise and
        # turned it back into a warning — so `strict=True` behaved identically to
        # `strict=False` through `protect()`, `gate()` and `Gate`, which is every entry
        # point the README teaches, while this class's own warning text recommended it
        # as the remedy. `AuditSink` is a Protocol, so a host's own sink opts into the
        # same contract just by carrying a truthy `strict`.
        self.strict = strict

    def _path_lock(self) -> threading.Lock:
        """The in-process lock for this log file, shared by every sink writing to it.

        A per-instance lock was the wrong scope on every platform. Two
        ``JSONLAuditSink`` objects on one path — two Gates in one process, the ordinary
        way a host separates a strict tool set from a lenient one — held different
        locks, so on POSIX they were serialised only by ``flock``, and where ``flock``
        is absent they were not serialised at all: interleaved appends, and a chain
        that ``histos audit verify`` then calls broken forever.

        Keyed through `_lock_key`, so two spellings of one file share a lock — two that
        differ only in case, which on macOS and Windows are the same file, and two that
        differ by a mount, which `realpath` cannot see through. Deliberately *not*
        `_path_key`: that one has to stay stable when a directory is recreated, which is
        the opposite property, and the two maps in that module are keyed apart for it.
        """
        key = _lock_key(self.path)
        with _PATH_LOCKS_GUARD:
            return _PATH_LOCKS.setdefault(key, threading.Lock())

    def _digest(self, body: str) -> str:
        return _chain_digest(body, self._key)

    def _tail(self, fh: Any) -> tuple[int, str]:
        """(seq, hash) of the last record in the open file — the only chain state."""
        last = _read_last_line(fh)
        if not last:
            return 0, ""
        try:
            rec = json.loads(last)
        except ValueError:
            return 0, ""
        if not isinstance(rec, dict):
            return 0, ""
        seq = rec.get("seq")
        return (seq if isinstance(seq, int) else 0), str(rec.get("hash", ""))

    def _write_tip(self, seq: int, tip: str) -> None:
        body = _tip_body(seq, tip)
        payload = json.dumps({"records": seq, "hash": tip, "mac": self._digest(body)})
        # Replaced, never edited in place: a reader that catches the file mid-write
        # must see the previous tip, not half of two.
        #
        # The temporary name carries pid and thread id because it used to be a fixed
        # `<log>.tip.new` and was only safe by accident — the `flock` below happens to
        # serialise POSIX writers. Where that lock is a no-op (Windows, some network
        # mounts) two writers raced on one path, one `os.replace` consumed the file and
        # the other raised `FileNotFoundError` out of `Gate._emit`. On the POST path
        # that lands *after* the tool has run, so the side effect happened, the caller
        # got an exception instead of the result, and the result was discarded — a
        # sink taking down the call it exists to record.
        tmp = self.tip_path.with_name(f"{self.tip_path.name}.{os.getpid()}.{threading.get_ident()}.new")
        try:
            # `os.replace` keeps the source's mode, so the scratch file has to be created
            # owner-only too or the sidecar arrives 0644 however the log was made.
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), self._mode)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload + "\n")
            os.replace(tmp, self.tip_path)
        finally:
            # A crash between write and replace would otherwise leave the scratch file
            # behind, and one per process-thread pair accumulates.
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)

    def _open_append(self) -> Any:
        """Open the log for append, creating it owner-only.

        `Path.open` cannot say what mode a file should be *created* with, so this goes
        through `os.open`. The mode argument is ignored for a file that already exists,
        which is the behaviour we want: this sets a safe default, it does not enforce a
        policy on a file the operator already owns.
        """
        # `O_BINARY` where it exists. On Windows the CRT fd defaults to text mode, so
        # `os.fdopen(fd, "a+b")` still translates `\n` to `\r\n` — this release added a
        # `.gitattributes` promising two machines agree on the same bytes while the
        # runtime writer would not have, and `_read_last_line` seeks by physical byte
        # offset against counts the write returns in logical ones.
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), self._mode)
        return os.fdopen(fd, "a+b")

    def record(self, entry: dict[str, Any]) -> None:
        """Append one record. Never raises — see below.

        `record()` runs from `Gate._emit` on the POST path as well as the PRE path, so
        it lands *after* the tool body has run. An exception out of here therefore does
        not prevent anything: the side effect already happened, and all it achieves is
        replacing the caller's result with a traceback and discarding the value the call
        produced — a sink taking down the calls it exists to record.

        One raise path out of this method was closed a release earlier (a fixed
        `.tip.new` scratch name that raced two writers into `FileNotFoundError`) and
        every sibling was left open: a log directory that becomes read-only, a path
        replaced by a directory, ENOSPC on the write, a `mode` the umask refuses. All
        of them were reachable mid-call and all of them cost the caller a completed
        result — measured, with the charge already made and the money gone.

        So the whole body is total. A failure increments :attr:`failed` and warns once
        per occurrence; it does not reach the caller. Losing a record is bad and is
        meant to be visible — `verify_chain` will also report the gap in the chain — but
        it is strictly better than losing the result of a call that already happened.
        """
        try:
            self._record(entry)
        except Exception as exc:  # noqa: BLE001 — totality is the point; see the docstring
            self.failed += 1
            # The count is deliberately out of the message: embedding it made every
            # failure a distinct string, which defeats the `once` filter and turns a
            # full disk into thousands of warnings. `failed` is the counter; this is the
            # signal that there is one to read.
            message = (
                f"histos: an audit record could not be written to {self.path} "
                f"({type(exc).__name__}: {exc}). The call itself was unaffected. "
                "Read JSONLAuditSink.failed for the count, or pass strict=True to raise instead."
            )
            # `-W error` promotes this to an exception, which made the totality above a
            # claim that held only under the default filters: the warning, not the write
            # failure, became the thing that took down a call whose side effect had
            # already happened. A filter is a reporting choice; `strict` is the one that
            # decides. So when the warning cannot be delivered it goes to stderr, which
            # cannot be turned into a raise.
            try:
                warnings.warn(message, RuntimeWarning, stacklevel=2)
            except Exception:  # noqa: BLE001 — see above; delivery must not decide the call
                with contextlib.suppress(Exception):
                    print(message, file=sys.stderr)
            if self.strict:
                raise

    def _record(self, entry: dict[str, Any]) -> None:
        payload = dict(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._path_lock(), self._open_append() as fh:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            if self.hash_chain:
                seq, prev = self._tail(fh)
                key = _path_key(self.path)
                high_seq, high_hash = _PATH_HIGH_WATER.get(key, (0, ""))
                # A shrink under a live sink is flagged, and external log rotation looks
                # exactly the same from in here — `rm` and `mv` both leave a fresh inode
                # at the same path, so the inode cannot tell them apart either. Flagging
                # is the direction to be wrong in: a rotated log reporting a broken chain
                # costs an operator an explanation they already have, and a missed
                # erasure costs the evidence.
                #
                # Which is why the remedy is `rotated()` and not something the file system
                # can be made to say. The docs used to offer "rotate the `.tip` sidecar
                # with the log" as the first of two remedies, and it simply did not work:
                # this memory is keyed by path and outlives both files, so a correctly
                # rotated log stayed broken forever. Making the inode decide would have
                # fixed that by handing the erasure back — `rm` produces a fresh inode
                # just as rotation does, which is the whole point of the paragraph above.
                # An explicit in-process call is the one signal an attacker rewriting
                # files on disk cannot produce.
                if seq < high_seq:
                    seq, prev = high_seq, high_hash
                payload["seq"] = seq + 1
                payload["prev"] = prev
                payload["hash"] = self._digest(json.dumps(payload, sort_keys=True, ensure_ascii=True))
            # `sort_keys=True` here as well as in the hashed body above, so the line on
            # disk and the line verification reconstructs are the same bytes. Without it
            # `verify_chain` authenticated a *re-serialisation* of the record and not the
            # file: a rewrite that reordered keys, or respaced the JSON, changed what
            # every reader and every grep sees while the chain still reported intact.
            line = json.dumps(payload, sort_keys=True, ensure_ascii=True) + "\n"
            # `surrogatepass` for the same reason as `digest_args`: an argument *key* can
            # carry a lone surrogate, and a sink that raises deletes the record. But
            # passing it through is what made the *file* the casualty instead: this used
            # to serialise with `ensure_ascii=False`, so `{"\ud800evil": 1}` — what every
            # framework's `json.loads` hands over for a lone-surrogate escape — put raw
            # ED A0 80 into an append-only log, and `for line in open(path)` then yielded
            # zero records, not one bad one, because Python decodes a whole 8 KiB buffer
            # at a time. `ensure_ascii=True` escapes it to \ud800 instead, so the file is
            # ASCII by construction and stays readable by an ordinary UTF-8 reader while
            # the record still says exactly what the model sent. Chosen over sanitising
            # the offending fields because it covers every field at once, including ones
            # added later, and loses no text. The hashed body above must use the same
            # setting or the chain would not verify against what is on disk.
            # All or nothing. `write` + `flush` is not failure-atomic: when the volume
            # fills mid-line the bytes already accepted stay in an append-only file with
            # no trailing newline, and every later append lands on that same physical
            # line. So one transient quota event did not cost one record — it cost the
            # log, permanently: `verify_chain` reported "not valid JSON" at that line and
            # never recovered, because each subsequent record was glued onto the torn one
            # and swallowed with it. Truncating back to where the line started leaves the
            # file exactly as it was, and the record is lost the ordinary way, through
            # `failed` and the gap the chain already reports.
            # Written straight to the descriptor, not through the buffered handle, and
            # that is the whole point rather than a style choice. `os.fdopen(fd, "a+b")`
            # is a `BufferedRandom` with an 8 KiB buffer, and a record is far smaller —
            # so `fh.write()` never reaches the disk and a full volume can only surface
            # from `fh.flush()`. CPython's flush advances over the bytes the raw layer
            # accepted and leaves the remainder *in the buffer*. The rollback below then
            # truncated the file back — freeing exactly the space the leftover needed —
            # and the `with` statement closed the handle, `close()` flushed, and the
            # buffered tail landed straight back on the file the rollback had just
            # repaired. The torn line this code exists to prevent, restored by the
            # cleanup. `os.write` on an `O_APPEND` descriptor leaves nothing anywhere
            # for `close()` to replay, and a short return is visible here where it can
            # be rolled back.
            start = os.fstat(fh.fileno()).st_size
            payload_bytes = line.encode("utf-8", "surrogatepass")
            try:
                written = os.write(fh.fileno(), payload_bytes)
                if written != len(payload_bytes):
                    raise OSError(errno.ENOSPC, f"wrote {written} of {len(payload_bytes)} bytes")
            except BaseException:
                with contextlib.suppress(OSError, ValueError):
                    os.ftruncate(fh.fileno(), start)
                raise
            if self.hash_chain:
                _PATH_HIGH_WATER[key] = (int(payload["seq"]), str(payload["hash"]))
                self._write_tip(payload["seq"], payload["hash"])

    def rotated(self) -> None:
        """Declare that this log was rotated deliberately, so the next chain starts clean.

        A sink remembers the highest ``seq`` it has written to a path, because that
        memory is the only thing left that contradicts a log erased together with its
        tip sidecar. Ordinary rotation is indistinguishable from that erasure on disk —
        `rm` and `mv` both leave a fresh inode at the same path — so a rotated log
        reports a broken chain, which is the safe direction to be wrong in but leaves
        the operator no way to say "that was me".

        This is that way, and it is a method rather than an inference precisely because
        an attacker rewriting files cannot call it: the signal comes from inside the
        process that owns the sink. Call it after the rotation, before the next call
        that will be recorded::

            os.rename(log, log.with_suffix(".jsonl.1"))
            os.rename(sink.tip_path, ...)
            sink.rotated()

        Pointing a new sink at the new path needs nothing — that path has no history.
        """
        # Under the same lock every other read and write of this map takes. Without it,
        # a `record()` already past its read of the mark and not yet at its write-back
        # re-inserts the pre-rotation `(seq, hash)` after the pop — and the next record
        # on the rotated log is numbered from the old chain again.
        with self._path_lock():
            _PATH_HIGH_WATER.pop(_path_key(self.path), None)

    def verify(self) -> bool:
        """Re-walk the file and confirm the hash chain is intact."""
        ok, _ = verify_chain(self.path, key=self._key)
        return ok
