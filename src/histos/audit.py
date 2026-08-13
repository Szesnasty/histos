"""The audit trail — the "Prove it" artifact.

Design points:

* **Records every decision, including DENIED.** Denied attempts are the whole
  value ("18 unauthorised attempts blocked").
* **Never stores raw argument values** — arguments can be PII. Each record keeps
  a keyed **HMAC-SHA256** digest of the arguments — a bare SHA of a low-entropy
  value is brute-forceable — plus the argument *keys*. That claim covers the
  *whole* record, not just the digest field, so a decision ``reason`` that quotes
  the offending value is rewritten on the way in — see :class:`AuditRecord`.
* **Verifiable, not "replayable".** You cannot reconstruct a call from a digest.
  What the trace lets you do is *verify* a decision: it records ``decision_id``,
  the ``policy_hash`` + ``policy_version`` + ``gate_version`` that produced it, the
  matched ``rule`` and the structured ``field/expected/received``.
* **Local and pluggable.** :class:`JSONLAuditSink` writes append-only JSONL with
  no proxy and no DB. :class:`InMemoryAuditSink` keeps a bounded window in memory —
  it is the default, so it must not be a leak in a long-lived server.
* **Optional tamper-evidence.** :class:`JSONLAuditSink` can hash-chain records.
* **Audit must never crash the gate, and never silently lose a record.** Both
  shipped sinks are safe to call from several threads, and the digest has no input
  it can refuse.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import sys
import threading
import warnings
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

try:  # POSIX only; Windows gets in-process locking and nothing more (documented).
    import fcntl
except ImportError:  # pragma: no cover - exercised only on Windows
    fcntl = None  # type: ignore[assignment]


def digest_args(args: dict[str, Any], key: bytes) -> str:
    """Keyed HMAC-SHA256 hex of the arguments — never the raw values.

    Uses the one canonical serializer (Phase 0.1), so two calls with the same arguments
    digest the same *under the same key*. It does not equal the approval fingerprint,
    which this used to claim: that one is an unkeyed SHA-256 over the tool, the args and
    the whole principal, and it exists to be reproducible by a host that never sees this
    key. Two different questions, two different values.

    The key matters more than it looks. `Gate` generates a random one per instance
    unless given `audit_key=`, which is right for the default — a bare SHA of a
    low-entropy argument is brute-forceable — but it means the column cannot be
    correlated across processes, across a restart, or between two Gates in one process
    unless the operator passes a stable key. Pass one from your secret store if
    "the same call, again" is a question you need the trail to answer.

    Audit must never crash the gate, so an un-canonicalizable value falls back to a
    stable repr rather than raising.
    """
    from histos.canonical import canonical_json

    try:
        canonical = canonical_json(args)
    except (TypeError, ValueError):
        canonical = repr(sorted(args.items(), key=lambda kv: kv[0]))
    # `surrogatepass`, because a plain `.encode("utf-8")` here is a way to make a
    # decision disappear. The serializer rejects a lone surrogate, but the repr
    # fallback does not: an argument object whose `__repr__` returns one produced a
    # `UnicodeEncodeError` out of `Gate._emit` *before* the sink was reached, so the
    # call that provoked it was the one call with no record at all. There is no input
    # this digest is allowed to refuse.
    return "hmac-sha256:" + hmac.new(key, canonical.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()


# Decision rules whose `reason` this module composes itself, out of things the record
# already publishes or the operator already has: tool names, the caller's role, policy
# literals the developer wrote, field names, limit names. Safe to keep verbatim.
#
# Absent from the list, and therefore redacted: every rule whose reason is built by
# interpolating a *foreign* string — an exception raised by a host resolver, a confirm
# callback, or a check that fell over. `KeyError('jane.doe@x.com')` is the ordinary
# shape of such an exception, and it is a raw argument value on its way into an
# append-only file. An unrecognised rule redacts too, so a rule added later is assumed
# to quote data until someone says otherwise.
_REASON_IS_POLICY_TEXT: frozenset[str] = frozenset(
    {
        "allow",
        "confirmed",
        "unknown_tool",
        "no_arg_schema",
        "no_principal",
        "rbac",
        "arg_schema",
        "arg_binding_unresolved",
        "resource_constraint",
        "no_resource_resolver",
        "canary_exfil",
        "secret_detected",
        "injection_pattern",
        "exfiltration_pattern",
        "rate_limit",
        "budget",
        "requires_confirmation",
        "post_redaction",
        "exception_redaction",
        "output_schema",
        # composed from the tool name and the *kind* of lazy value that came back
        # ("generator", "structure containing a memoryview …") — never from the value,
        # which is the one thing the gate could not read in the first place.
        "uninspectable_output",
        # tool name and a count of positional arguments; no value is quoted.
        "confirm_suspended",
        "unnameable_args",
    }
)

_REDACTED = "[redacted — this rule's reason quotes foreign text; it stays in the developer channel]"

# `arg_keys` is the one field made entirely of model-chosen text, and it used to be
# copied in whole: a call with ten thousand one-kilobyte argument names wrote a ten-
# megabyte line into an append-only file, once per decision, for free. Caps here rather
# than at the sink so every sink gets them, and truncation is announced in the record
# instead of leaving a short list that reads like a short call.
_MAX_ARG_KEYS = 64
_MAX_ARG_KEY_LEN = 128
_MAX_ARG_KEYS_TOTAL = 1024

# Capping only `arg_keys` turned out to be the shape of the bug rather than the fix.
# The other text fields are copied in whole from the same places: `tool` is whatever
# name the host wrapped (a 200,000-character tool name is a 200,000-character field),
# `identity` and `role` come from a Principal a host may build out of a token claim,
# `field_name` is frequently the model's own argument name, and `reason` INTERPOLATES
# those — so a single call still wrote an 800 KB line with `arg_keys` dutifully capped
# at 1 KB inside it. Every free-text field is bounded here, and a clipped string keeps
# a marker so a truncated value is never read as the whole one. Chosen over a
# `<field>_truncated` flag per field: the marker travels with the text through every
# sink, dashboard and grep, none of which know about a new column.
_MAX_NAME_LEN = 256
_MAX_TEXT_LEN = 512
_TRUNCATED = "...[truncated]"


def _cap_arg_keys(keys: list[str]) -> tuple[list[str], bool]:
    """Bound an attacker-sized ``arg_keys`` list; returns (kept, truncated)."""
    kept: list[str] = []
    budget = _MAX_ARG_KEYS_TOTAL
    for key in keys[:_MAX_ARG_KEYS]:
        clipped = key[:_MAX_ARG_KEY_LEN]
        if len(clipped) > budget:
            break
        budget -= len(clipped)
        kept.append(clipped)
    return kept, kept != keys


def _cap_text(value: str, limit: int) -> str:
    """Bound one free-text field, leaving the clipping visible in the value itself."""
    return value if len(value) <= limit else value[:limit] + _TRUNCATED


@dataclass
class AuditRecord:
    """One gate decision, ready to serialise.

    The record is the **durable** channel, and it is held to the module's headline
    claim: no raw argument value reaches it, in any field. The engine's own denial
    text names rules and fields without quoting values, but a reason that carries a
    *foreign* exception (`resource_resolver raised: KeyError('jane.doe@x.com')`) does
    quote one, and copying that into an append-only file on disk is the outcome the
    argument digest exists to prevent. Those reasons are dropped here; the decision
    keeps its `rule`, `field` and `expected`, and the full text stays on the
    in-process `GateDenied.decision` where a developer debugging the denial reads it.
    """

    ts: float
    decision_id: int
    phase: str  # "pre" | "post"
    tool: str
    role: str
    identity: str | None
    effect: str
    rule: str
    reason: str
    args_digest: str
    arg_keys: list[str] = field(default_factory=list)
    #: Whether `arg_keys` was clipped on the way in — see :data:`_MAX_ARG_KEYS`. A record
    #: listing 64 keys is otherwise indistinguishable from a call that had exactly 64.
    arg_keys_truncated: bool = False
    #: Arguments the policy *overwrote* with a trusted principal attribute before the
    #: tool saw them — field names only, never values.
    #:
    #: A binding is an authorization decision, and it used to leave no trace. A run in
    #: which the gate silently redirected a message from an attacker's number to the
    #: caller's own recorded `effect=allow` and nothing else, which is
    #: indistinguishable in the trail from a call the policy had no opinion about. An
    #: auditor asking "why did this not go where the model asked" had nothing to read,
    #: and a measurement could not attribute the absence of harm to the policy.
    #:
    #: Only fields whose value actually changed are listed. A bound field the caller
    #: already had right was not overridden, and counting it would inflate the number
    #: of interventions the gate appears to have made.
    rebound_args: list[str] = field(default_factory=list)
    field_name: str = ""
    expected: str = ""
    received: str = ""
    redactions: list[str] = field(default_factory=list)
    enforced: bool = True
    # Whether the tool body actually ran for this call. In observe mode a DENY
    # still executes, so `effect=deny enforced=false executed=true` is the record
    # that must never be mistaken for a block.
    executed: bool = True
    latency_us: int | None = None
    policy_hash: str = ""
    policy_version: str = ""
    gate_version: str = ""

    def __post_init__(self) -> None:
        self.arg_keys, self.arg_keys_truncated = _cap_arg_keys(self.arg_keys)
        if self.rule not in _REASON_IS_POLICY_TEXT:
            self.reason = _REDACTED
            # `received` is shape-only everywhere the engine sets it (`resource.<field>`,
            # a detector kind, the caller's role), but it is held to the same rule as
            # the reason rather than trusted to stay that way.
            self.received = _REDACTED if self.received else ""
        # after the redaction, so a dropped reason is never clipped into something that
        # looks like half of a real one.
        self.tool = _cap_text(self.tool, _MAX_NAME_LEN)
        self.role = _cap_text(self.role, _MAX_NAME_LEN)
        if self.identity is not None:
            self.identity = _cap_text(self.identity, _MAX_NAME_LEN)
        self.field_name = _cap_text(self.field_name, _MAX_NAME_LEN)
        self.reason = _cap_text(self.reason, _MAX_TEXT_LEN)
        self.expected = _cap_text(self.expected, _MAX_TEXT_LEN)
        self.received = _cap_text(self.received, _MAX_TEXT_LEN)
        # `redactions` was missed by the cap pass that bounded every other free-text
        # field, and it is the one built from the *output*: `drop:<key>` carries a raw
        # return-value key, `output:uninspectable:<type>` a type name, and a projected
        # dict with ten thousand undeclared keys writes ten thousand of them into an
        # append-only file. Same budget, same visible marker.
        self.redactions, clipped = _cap_arg_keys(list(self.redactions))
        if clipped:
            self.redactions.append("...[truncated]")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@runtime_checkable
class AuditSink(Protocol):
    def record(self, entry: dict[str, Any]) -> None: ...


# A default that grows forever is not a safe default. `protect(my_tools, policy=...)`
# installs this sink when the caller says nothing, and two records per call over a
# week of traffic is a leak proportional to how much the gate is used.
_DEFAULT_MAX_ENTRIES = 10_000


class InMemoryAuditSink:
    """Keeps recent records in memory — the default, and what tests assert against.

    Bounded: the oldest record is dropped once ``maxlen`` is reached, and
    :attr:`dropped` counts how many were lost so the gap is visible rather than
    silent. Pass ``maxlen=None`` for the old unbounded behaviour, and use
    :class:`JSONLAuditSink` for anything that has to keep the whole trace.

    Thread-safe: ``record`` holds ``_lock``.
    """

    def __init__(self, maxlen: int | None = _DEFAULT_MAX_ENTRIES) -> None:
        self.entries: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self.dropped = 0
        self._lock = threading.Lock()

    def record(self, entry: dict[str, Any]) -> None:
        with self._lock:
            if self.entries.maxlen is not None and len(self.entries) == self.entries.maxlen:
                self.dropped += 1
            self.entries.append(entry)

    @property
    def denied(self) -> list[dict[str, Any]]:
        return [e for e in self.entries if e["effect"] == "deny"]


# One lock per log file, process-wide. Keyed by resolved path so two sinks pointed at
# the same file cannot interleave, which a per-instance lock allowed.
_PATH_LOCKS: dict[str, threading.Lock] = {}
_PATH_LOCKS_GUARD = threading.Lock()

# The highest (seq, hash) written to each log by this process. Per path rather
# than per sink: the memory is the whole erasure defence, and a second `JSONLAuditSink`
# on the same file — two Gates in one host, which the lock above exists for — started
# with an empty one and happily wrote a fresh chain over a truncated file. Scoped like
# the lock that protects it.
_PATH_HIGH_WATER: dict[str, tuple[int, str]] = {}


def _duplicate_key(line: str) -> str | None:
    """The first key repeated in one JSON object of ``line``, or None.

    `json.loads` keeps the last value for a repeated key and a human reading the file
    sees the first, which is the one way a line and the record it parses to can say
    different things. `object_pairs_hook` is handed every pair before that collapse
    happens, which is the only place the difference is still visible.
    """
    found: list[str] = []

    def check(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        for key, _ in pairs:
            if key in seen:
                found.append(key)
            seen.add(key)
        return dict(pairs)

    try:
        json.loads(line, object_pairs_hook=check)
    except ValueError:  # already reported as unparseable by the caller
        return None
    return found[0] if found else None


def _path_key(path: Path) -> str:
    """The identity of a log file, for the two module-level maps keyed on it.

    `str(path.resolve())` was the key and it does not canonicalise *case* — and macOS
    APFS and every Windows volume are case-insensitive. So `Trail.jsonl` and
    `trail.jsonl` are one file with two keys: the erasure memory that
    `_PATH_HIGH_WATER` exists to be is defeated by one capital letter, and `_PATH_LOCKS`
    hands two sinks on one file two different locks — on Windows, where `flock` is
    absent, leaving nothing at all serialising them. Both on exactly the two platforms
    this release added to CI.
    """
    resolved = os.path.realpath(path)
    # `os.path.normcase` is a no-op on POSIX — it folds case only on Windows — so it
    # does nothing on macOS, which is where this was demonstrated. Folded on the two
    # platforms whose filesystems are case-insensitive by default, which are the two
    # this release added to CI. A case-sensitive APFS volume would over-merge two logs
    # in one directory differing only in case; that is a pathological place to keep an
    # audit trail, and the failure direction is the safe one — a chain reported broken
    # rather than an erasure missed.
    return resolved.casefold() if sys.platform in ("darwin", "win32") else resolved


def tip_path_for(log: str | Path) -> Path:
    """The sidecar that binds a hash-chained log to its length. See :class:`JSONLAuditSink`."""
    p = Path(log)
    return p.with_name(p.name + ".tip")


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
        self._strict = strict

    def _path_lock(self) -> threading.Lock:
        """The in-process lock for this log file, shared by every sink writing to it.

        A per-instance lock was the wrong scope on every platform. Two
        ``JSONLAuditSink`` objects on one path — two Gates in one process, the ordinary
        way a host separates a strict tool set from a lenient one — held different
        locks, so on POSIX they were serialised only by ``flock``, and where ``flock``
        is absent they were not serialised at all: interleaved appends, and a chain
        that ``histos audit verify`` then calls broken forever.

        Keyed through `_path_key`, so two spellings of one file share a lock — including
        two that differ only in case, which on macOS and Windows are the same file and
        used to get two locks and, where `flock` is absent, no serialisation at all.
        """
        key = _path_key(self.path)
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
            warnings.warn(
                f"histos: an audit record could not be written to {self.path} "
                f"({type(exc).__name__}: {exc}). The call itself was unaffected. "
                "Read JSONLAuditSink.failed for the count, or pass strict=True to raise instead.",
                RuntimeWarning,
                stacklevel=2,
            )
            if self._strict:
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
            start = os.fstat(fh.fileno()).st_size
            try:
                fh.write(line.encode("utf-8", "surrogatepass"))
                fh.flush()
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
        _PATH_HIGH_WATER.pop(_path_key(self.path), None)

    def verify(self) -> bool:
        """Re-walk the file and confirm the hash chain is intact."""
        ok, _ = verify_chain(self.path, key=self._key)
        return ok


def _chain_digest(body: str, key: bytes | None) -> str:
    raw = body.encode("utf-8", "surrogatepass")
    if key is not None:
        return hmac.new(key, raw, hashlib.sha256).hexdigest()
    return hashlib.sha256(raw).hexdigest()


def _tip_body(seq: int, tip: str) -> str:
    # Domain-separated from a record body so a record can never be replayed as a tip.
    return f"histos-audit-tip:v1:{seq}:{tip}"


def _read_last_line(fh: Any) -> str:
    """Last non-empty line of an open binary file, read from the end."""
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    data = b""
    while size > 0:
        step = min(4096, size)
        size -= step
        fh.seek(size)
        data = fh.read(step) + data
        if data.count(b"\n") >= 2:
            break
    for chunk in reversed(data.split(b"\n")):
        if chunk.strip():
            return chunk.decode("utf-8", "surrogatepass")
    return ""


def verify_chain(path: str | Path, *, key: bytes | None = None) -> tuple[bool, str]:
    """Re-walk a hash-chained JSONL audit log; return (ok, human-readable detail).

    Reports the FIRST broken link (line number + why): a recomputed-hash mismatch,
    a broken `prev` pointer, an out-of-order `seq`, or an unparseable line. This is
    what ``histos audit verify`` prints. Honest scope: it proves the ordering,
    integrity and **length** of the trace — a record removed from the end no longer
    passes, because the ``<log>.tip`` sidecar binds the count. It still cannot prove
    a decision was ever written (an unwritten record leaves no gap), and unkeyed it
    only resists accident, not a motivated writer (pass a key for real
    tamper-evidence).
    """
    p = Path(path)
    if not p.exists():
        return False, f"audit file not found: {p}"

    prev = ""
    count = 0
    with p.open("rb") as fh:
        for lineno, raw in enumerate(fh, start=1):
            stripped = raw.decode("utf-8", "surrogatepass").strip()
            if not stripped:
                continue
            try:
                rec = json.loads(stripped)
            except ValueError as exc:
                return False, f"line {lineno}: not valid JSON ({exc})"
            if "hash" not in rec:
                return False, f"line {lineno}: record is not hash-chained (no `hash`)"
            stored = rec.pop("hash")
            if rec.get("prev", "") != prev:
                return False, f"line {lineno}: broken chain — `prev` does not match the previous record's hash"
            count += 1
            # `seq` lives inside the hashed body, so record N cannot be re-presented
            # as record N-2 even by someone who can recompute the chain.
            seq = rec.get("seq")
            if seq != count:
                if seq is None:
                    return False, f"line {lineno}: record carries no `seq` — it predates the numbered chain"
                return False, f"line {lineno}: record {count} is numbered {seq!r} — records were removed"
            # `record` hashes the ASCII serialisation now (see there). Logs written before
            # that hashed the identical record with `ensure_ascii=False`, and the two
            # bodies differ the moment any field holds a non-ASCII codepoint — so the old
            # spelling is accepted as a fallback rather than every pre-existing log
            # reporting "altered after it was written". Both are faithful serialisations of
            # the same parsed record, so accepting either forges nothing.
            body = json.dumps(rec, sort_keys=True, ensure_ascii=True)
            legacy_body = json.dumps(rec, sort_keys=True, ensure_ascii=False)
            canonical = hmac.compare_digest(_chain_digest(body, key), str(stored))
            matched = canonical or (
                legacy_body != body and hmac.compare_digest(_chain_digest(legacy_body, key), str(stored))
            )
            # A digest over the *parsed* record says nothing about the bytes a reader
            # sees. Two lines can parse to one dict and read differently — a repeated
            # key, where `json.loads` keeps the last and a human greps the first, is the
            # sharp case: the record verifies as `allow` while the file says `deny`. So
            # the line has to be a serialisation of the record it parses to.
            #
            # Which serialisation, though, is not something the check gets to dictate.
            # Requiring today's exact spelling looked safe because a legacy line was
            # thought to be "a different spelling by construction" — true only for the
            # records with a non-ASCII field, which is the rare case. For an ordinary
            # ASCII record the two bodies are byte-identical, so the legacy hash *is*
            # today's hash, the check fired, and `histos audit verify` told the operator
            # their untouched pre-0.1.0 log had been rewritten. That is a false accusation
            # about evidence, which is worse than the rewrite it was looking for.
            #
            # So: accept any spelling `json.dumps` can produce from the parsed record,
            # and run the check on every line rather than only on ones matching today's
            # digest — which also closes the legacy tamper hole that exemption left. The
            # sharp case is still caught: `json.loads` keeps document order, so an
            # unsorted dump reproduces legacy bytes exactly, while no dump of a parsed
            # dict can ever reproduce a duplicated key.
            # The real question is narrower than "is this the spelling we would have
            # written". Requiring one of four `json.dumps` spellings invented an
            # unwritten normative byte format and reported every other conformant
            # serialisation — a different key order, `separators=(",",":")`, a second
            # implementation's writer — as tampering. `spec/` describes no audit-log
            # byte format at all, so there is nothing to hold a line to.
            #
            # What the check exists for is the case where the bytes and the parsed record
            # *disagree*, and there is exactly one way for that to happen in JSON: a
            # repeated key, where `json.loads` keeps the last and a human greps the
            # first, so the record verifies as `allow` while the file says `deny`. Asked
            # directly, and nothing else is second-guessed.
            duplicate = _duplicate_key(stripped)
            if duplicate is not None:
                return False, (
                    f"line {lineno}: the record on disk repeats the key {duplicate!r}, so what a reader sees "
                    "and what the chain authenticates are different values"
                )
            if not matched:
                return False, f"line {lineno}: hash mismatch — record was altered after it was written"
            prev = str(stored)

    ok, detail = _verify_tip(p, count, prev, key)
    if not ok:
        return False, detail
    keyed = "keyed (HMAC)" if key is not None else "unkeyed (accident-evident only)"
    return True, f"OK — {count} records, chain intact, {keyed}"


def _verify_tip(log: Path, count: int, tip: str, key: bytes | None) -> tuple[bool, str]:
    """Confirm the log still ends where its sidecar says it does."""
    sidecar = tip_path_for(log)
    if not sidecar.exists():
        return False, (
            f"no tip file at {sidecar.name} — the chain proves the order of what is present, "
            "not that the end of the log is still there; truncation cannot be ruled out"
        )
    try:
        rec = json.loads(sidecar.read_text(encoding="utf-8"))
        expected_count = int(rec["records"])
        expected_tip = str(rec["hash"])
        mac = str(rec["mac"])
    except (ValueError, TypeError, KeyError, OSError) as exc:
        return False, f"tip file {sidecar.name} is unreadable ({exc})"
    if not hmac.compare_digest(_chain_digest(_tip_body(expected_count, expected_tip), key), mac):
        return False, f"tip file {sidecar.name} does not authenticate — it was altered, or the key is wrong"
    if expected_count != count or expected_tip != tip:
        removed = expected_count - count
        if removed > 0:
            return False, f"log ends at record {count} but the tip covers {expected_count} — {removed} removed"
        return False, f"log has {count} records but the tip covers {expected_count} — a write was interrupted"
    return True, ""
