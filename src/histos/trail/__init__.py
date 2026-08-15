"""The evidence: one row per decision, appended where it cannot be quietly rewritten.

This is the artifact somebody will be asked to trust in an argument, which is the whole
design brief. Three things follow from it.

A record never stores a raw argument value, and that covers the *whole* row rather than
the digest column — a decision `reason` quoting the value it refused is the same leak by
another name.

The trail is tamper-*evident*, not tamper-proof: a hash chain proves the order of what
is present, the sidecar is what makes a truncation visible, and neither stops someone
with write access from deleting the file. What they do is make the deletion legible.

And writing it must never decide a call. An exception out of `record()` runs on the POST
path, after the side effect, so it costs a completed call its result and prevents
nothing. `strict` is the one way that changes, for a host whose evidence requirement
outranks its availability.
"""

from histos.trail.audit import AuditSink, InMemoryAuditSink
from histos.trail.auditrecord import AuditRecord, digest_args
from histos.trail.jsonlsink import JSONLAuditSink
from histos.trail.logpath import tip_path_for
from histos.trail.verify import verify_chain

__all__ = [
    "AuditRecord",
    "AuditSink",
    "InMemoryAuditSink",
    "JSONLAuditSink",
    "digest_args",
    "tip_path_for",
    "verify_chain",
]
