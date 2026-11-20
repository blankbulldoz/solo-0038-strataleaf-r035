import base64
import hashlib
import hmac
from .codec import digest, dumps, key as checked_key, loads, name
from .cursors import decode_cursor
from .errors import Conflict, InvalidDocument, MirrorError, NotFound, SnapshotTooOld
from .mvcc import checked_revision, visible_rows
from .predicates import matches, validate_predicate

PHASE_ACTIVE = "active"          # consuming pages of the pinned read view
PHASE_REBASING = "rebasing"      # old view abandoned; reconciling onto a fixed new view
PHASE_SYNCED = "synced"          # whole fixed view verified against the local mirror

TOMBSTONE_DIGEST = ""


def _token(store, payload):
    raw = dumps(payload).encode()
    signature = hmac.new(bytes.fromhex(store.get("cursor_secret")), raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature + raw).decode().rstrip("=")


def _untoken(store, token):
    try:
        if not isinstance(token, str) or len(token) > 8192:
            raise ValueError("invalid token length")
        data = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        signature, raw = data[:32], data[32:]
        expected = hmac.new(bytes.fromhex(store.get("cursor_secret")), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature mismatch")
        payload = loads(raw)
        if not isinstance(payload, dict) or payload.get("database") != store.get("database_id"):
            raise ValueError("wrong database")
        return payload
    except (ValueError, TypeError, KeyError, UnicodeDecodeError) as exc:
        raise MirrorError("invalid or foreign mirror handoff token") from exc


class Mirror:
    """Receiver-side resumable mirror of a predicate-scoped, fixed read view.

    The mirror is driven only by identity-bearing, per-key upsert/tombstone actions.
    Every accepted action is durably recorded with its confirmed source revision and
    body digest, so duplicate deliveries are harmless and an interrupted correction can
    resume. A view that aged past the source floor is never silently advanced: callers
    must explicitly restart onto a new fixed view, which reconciles the whole view
    (revoking keys that disappeared, re-applying recreated keys, and catching keys that
    sort before the old pagination boundary).

    The source view (identified by ``target_rev``) and the local mirror collection
    (written under independent local revisions) are separate facts: completion is only
    claimed after the actual local rows are compared against the whole source view.
    """

    def __init__(self, store):
        self.store = store

    # ------------------------------------------------------------------ internal
    def _session(self, connection, session_name):
        row = connection.execute("SELECT * FROM mirror_sessions WHERE name=?", (session_name,)).fetchone()
        if row is None:
            raise NotFound("unknown mirror session: " + session_name)
        return row

    def _source_view(self, connection, session):
        """The authoritative key -> (source rev, digest, document, expires) view."""
        target = session["target_rev"]
        predicate = loads(session["predicate"])
        wanted = {}
        for row in visible_rows(connection, session["source_collection"], target):
            if row["body"] is None:
                continue
            document = loads(row["body"])
            if not matches(document, predicate):
                continue
            wanted[row["key"]] = (row["rev"], digest(document), document, row["expires"])
        return wanted

    def _view_digest(self, wanted):
        content = [{"key": action_key, "revision": source_rev, "body_digest": body_digest}
                   for action_key, (source_rev, body_digest, _document, _expires) in sorted(wanted.items())]
        return digest(content), len(content)

    def _local_live(self, connection, collection):
        """Actual live rows of the local mirror collection, keyed by document key."""
        rows = connection.execute(
            "SELECT v.* FROM versions v JOIN "
            "(SELECT key,MAX(rev) AS r FROM versions WHERE collection=? GROUP BY key) latest "
            "ON v.collection=? AND v.key=latest.key AND v.rev=latest.r WHERE v.body IS NOT NULL",
            (collection, collection)).fetchall()
        return {row["key"]: row for row in rows}

    def read_mirror(self, session_name, key):
        """Read the actual current mirrored value for a key (None when tombstoned/absent).

        The mirror collection lives in its own local revision space, so source revisions
        cannot address its rows; this reads the latest local version of the key.
        """
        with self.store.read() as connection:
            session = self._session(connection, session_name)
            row = connection.execute(
                "SELECT * FROM versions WHERE collection=? AND key=? ORDER BY rev DESC LIMIT 1",
                (session["collection"], checked_key(key))).fetchone()
            if row is None or row["body"] is None:
                return None
            from .mvcc import record
            return record(row)

    def _next_local_rev(self, connection):
        row = connection.execute("SELECT COALESCE(MAX(local_rev),0) AS m FROM mirror_entries").fetchone()
        return row["m"] + 1

    def _apply_actions(self, connection, session, actions):
        collection = session["collection"]
        applied = 0
        for action in actions:
            if not isinstance(action, dict) or \
               set(action) - {"key", "op", "revision", "body_digest", "document", "expires_at"}:
                raise InvalidDocument("mirror action has unknown fields")
            op = action.get("op")
            if op not in ("upsert", "tombstone"):
                raise InvalidDocument("mirror action op must be upsert or tombstone")
            action_key = checked_key(action.get("key"))
            source_rev = action.get("revision")
            if isinstance(source_rev, bool) or not isinstance(source_rev, int) or source_rev <= 0:
                raise InvalidDocument("mirror action revision must be a positive integer")
            entry = connection.execute("SELECT * FROM mirror_entries WHERE session=? AND key=?",
                                       (session["name"], action_key)).fetchone()
            if op == "upsert":
                document = action.get("document")
                if not isinstance(document, dict):
                    raise InvalidDocument("upsert action requires a document object")
                claimed = action.get("body_digest")
                actual = digest(document)
                if not isinstance(claimed, str) or claimed != actual:
                    raise MirrorError("action body digest does not match its document for key " + action_key)
                expires_at = action.get("expires_at")
                # Duplicate delivery of an already confirmed, identical action is a no-op.
                if entry is not None and entry["source_rev"] == source_rev and entry["body_digest"] == actual:
                    continue
                # Every material change appends a new local revision, preserving the
                # per-key version chain (including tombstone-then-recreate preconditions).
                local_rev = self._next_local_rev(connection)
                connection.execute(
                    "INSERT INTO versions(collection,key,rev,body,expires) VALUES(?,?,?,?,?)",
                    (collection, action_key, local_rev, dumps(document), expires_at))
                connection.execute(
                    "INSERT INTO mirror_entries(session,key,source_rev,local_rev,body_digest) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(session,key) DO UPDATE SET source_rev=excluded.source_rev,"
                    "local_rev=excluded.local_rev,body_digest=excluded.body_digest",
                    (session["name"], action_key, source_rev, local_rev, actual))
            else:
                if entry is None:
                    continue  # tombstone for a key never confirmed: nothing to revoke
                if entry["body_digest"] == TOMBSTONE_DIGEST and entry["source_rev"] == source_rev:
                    continue  # duplicate tombstone already confirmed
                local_rev = self._next_local_rev(connection)
                connection.execute(
                    "INSERT INTO versions(collection,key,rev,body,expires) VALUES(?,?,?,NULL,NULL)",
                    (collection, action_key, local_rev))
                connection.execute(
                    "INSERT INTO mirror_entries(session,key,source_rev,local_rev,body_digest) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(session,key) DO UPDATE SET source_rev=excluded.source_rev,"
                    "local_rev=excluded.local_rev,body_digest=excluded.body_digest",
                    (session["name"], action_key, source_rev, local_rev, TOMBSTONE_DIGEST))
            applied += 1
        return applied

    def _reconcile(self, connection, session):
        """Full re-scan of the fixed new view; corrects the mirror in key order."""
        wanted = self._source_view(connection, session)
        # Revoke confirmed-live keys that disappeared from the view or no longer match.
        stale = connection.execute(
            "SELECT key FROM mirror_entries WHERE session=? AND body_digest<>? ORDER BY key",
            (session["name"], TOMBSTONE_DIGEST)).fetchall()
        revoked = 0
        for row in stale:
            action_key = row["key"]
            if action_key in wanted:
                continue
            local_rev = self._next_local_rev(connection)
            connection.execute(
                "INSERT INTO versions(collection,key,rev,body,expires) VALUES(?,?,?,NULL,NULL)",
                (session["collection"], action_key, local_rev))
            connection.execute(
                "UPDATE mirror_entries SET local_rev=?, body_digest=? WHERE session=? AND key=?",
                (local_rev, TOMBSTONE_DIGEST, session["name"], action_key))
            revoked += 1
        # Apply (or re-apply) every live key, including recreated keys and keys before
        # the old pagination boundary. Identity digest checks reject tampered content.
        actions = [{"key": action_key, "op": "upsert", "revision": source_rev,
                    "body_digest": body_digest, "document": document, "expires_at": expires_at}
                   for action_key, (source_rev, body_digest, document, expires_at) in wanted.items()]
        applied = self._apply_actions(connection, session, actions)
        return revoked, applied, len(wanted)

    # ------------------------------------------------------------------ lifecycle
    def open(self, session_name, source_collection, mirror_collection, predicate=None):
        name(session_name)
        name(source_collection)
        name(mirror_collection)
        validate_predicate(predicate)
        fingerprint = digest({"collection": source_collection, "predicate": predicate})
        with self.store.atomic(writable=True) as connection:
            if not connection.execute("SELECT 1 FROM collections WHERE name=?",
                                      (source_collection,)).fetchone():
                raise NotFound("unknown source collection: " + source_collection)
            if not connection.execute("SELECT 1 FROM collections WHERE name=?",
                                      (mirror_collection,)).fetchone():
                raise NotFound("unknown mirror collection: " + mirror_collection)
            if connection.execute("SELECT 1 FROM mirror_sessions WHERE name=?", (session_name,)).fetchone():
                raise Conflict("mirror session already exists: " + session_name)
            head, floor = int(self.store.get("head")), int(self.store.get("floor"))
            connection.execute(
                "INSERT INTO mirror_sessions(name,source_collection,collection,predicate,"
                "predicate_fingerprint,source_id,target_rev,source_floor,after_key,phase,"
                "view_digest,key_count,certificate) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (session_name, source_collection, mirror_collection, dumps(predicate), fingerprint,
                 self.store.get("database_id"), head, floor, None, PHASE_ACTIVE, None, None, None))
            return self._status(connection, session_name)

    def status(self, session_name):
        with self.store.read() as connection:
            return self._status(connection, session_name)

    def _status(self, connection, session_name):
        session = self._session(connection, session_name)
        confirmed = connection.execute(
            "SELECT COUNT(*) AS c, SUM(CASE WHEN body_digest=? THEN 1 ELSE 0 END) AS t "
            "FROM mirror_entries WHERE session=?", (TOMBSTONE_DIGEST, session_name)).fetchone()
        return {"session": session_name, "source_collection": session["source_collection"],
                "collection": session["collection"],
                "predicate": loads(session["predicate"]),
                "predicate_fingerprint": session["predicate_fingerprint"],
                "source": session["source_id"], "target_revision": session["target_rev"],
                "source_floor": session["source_floor"], "phase": session["phase"],
                "after_key": session["after_key"],
                "confirmed_keys": confirmed["c"], "live_keys": confirmed["c"] - (confirmed["t"] or 0),
                "tombstoned_keys": confirmed["t"] or 0,
                "view_digest": session["view_digest"], "key_count": session["key_count"],
                "certificate": loads(session["certificate"]) if session["certificate"] else None}

    def _status_row(self, connection, session_name, applied, revoked):
        session = self._session(connection, session_name)
        confirmed = connection.execute(
            "SELECT COUNT(*) AS c, SUM(CASE WHEN body_digest=? THEN 1 ELSE 0 END) AS t "
            "FROM mirror_entries WHERE session=?", (TOMBSTONE_DIGEST, session_name)).fetchone()
        return {"session": session_name, "phase": session["phase"], "applied": applied, "revoked": revoked,
                "target_revision": session["target_rev"], "after_key": session["after_key"],
                "confirmed_keys": confirmed["c"], "live_keys": confirmed["c"] - (confirmed["t"] or 0),
                "synced": session["phase"] == PHASE_SYNCED}

    def apply_page(self, session_name, envelope):
        if not isinstance(envelope, dict):
            raise InvalidDocument("mirror envelope must be an object")
        with self.store.atomic(writable=True) as connection:
            session = self._session(connection, session_name)
            try:
                if envelope.get("kind") != "mirror_page":
                    raise MirrorError("envelope is not a mirror page")
                if envelope.get("source") != self.store.get("database_id") or \
                   session["source_id"] != envelope.get("source"):
                    raise MirrorError("envelope source identity does not match this database/session")
                if envelope.get("collection") != session["source_collection"]:
                    raise MirrorError("envelope collection does not match the session source")
                if envelope.get("predicate_fingerprint") != session["predicate_fingerprint"]:
                    raise MirrorError("envelope predicate does not match the session")
                revision = envelope["revision"]
                floor = envelope["floor"]
                if isinstance(revision, bool) or not isinstance(revision, int):
                    raise InvalidDocument("envelope revision must be an integer")
                if isinstance(floor, bool) or not isinstance(floor, int):
                    raise InvalidDocument("envelope floor must be an integer")
                # Strict snapshot semantics: a reclaimed view is rejected, never advanced.
                checked_revision(self.store, revision)
                if revision < floor:
                    raise SnapshotTooOld(
                        f"page view revision {revision} is older than source floor {floor}")
                target = session["target_rev"]
                phase = session["phase"]
                actions = envelope.get("actions")
                if not isinstance(actions, list) or len(actions) > 1000:
                    raise InvalidDocument("envelope actions must be a list of at most 1000")
                if phase == PHASE_ACTIVE:
                    if revision != target:
                        raise MirrorError(
                            "page belongs to a different read view; restart the mirror onto the new view")
                    cursor = envelope.get("cursor")
                    if cursor is not None:
                        payload = decode_cursor(self.store, cursor)
                        if payload.get("kind") != "mirror_page" or \
                           payload.get("query") != session["predicate_fingerprint"]:
                            raise MirrorError("cursor does not belong to this mirror export")
                        if payload.get("revision") != revision:
                            raise MirrorError("cursor is pinned to another read revision")
                    keys = [a.get("key") for a in actions if isinstance(a, dict)]
                    if any(not isinstance(k, str) for k in keys) or len(keys) != len(set(keys)):
                        raise InvalidDocument("a page must contain distinct string keys")
                    # Re-delivered pages are accepted: per-key revision/digest identity in
                    # _apply_actions makes every repeated action an idempotent no-op.
                    applied = self._apply_actions(connection, session, actions)
                    if keys:
                        connection.execute("UPDATE mirror_sessions SET after_key=? WHERE name=?",
                                           (keys[-1], session_name))
                    if cursor is None:
                        self._finish_view(connection, self._session(connection, session_name))
                    return self._status_row(connection, session_name, applied, 0)
                if phase == PHASE_REBASING:
                    if revision != target:
                        raise MirrorError(
                            "rebasing pages must target the new fixed view revision " + str(target))
                    applied = self._apply_actions(connection, session, actions)
                    return self._status_row(connection, session_name, applied, 0)
                raise MirrorError("mirror is already synced; abandon and reopen to start a new mirror")
            except (KeyError, TypeError) as exc:
                raise MirrorError("malformed mirror envelope") from exc

    def _finish_view(self, connection, session):
        """Compare the whole source view against the actual local mirror before claiming sync."""
        wanted = self._source_view(connection, session)
        view_digest, key_count = self._view_digest(wanted)
        local_live = self._local_live(connection, session["collection"])
        entries = {row["key"]: row for row in connection.execute(
            "SELECT * FROM mirror_entries WHERE session=?", (session["name"],)).fetchall()}
        for action_key, (source_rev, body_digest, document, _expires) in wanted.items():
            entry = entries.get(action_key)
            local = local_live.get(action_key)
            if entry is None or entry["body_digest"] == TOMBSTONE_DIGEST or \
               entry["source_rev"] != source_rev or entry["body_digest"] != body_digest:
                raise MirrorError("mirror does not cover the complete fixed view; refusing to mark synced")
            if local is None or digest(loads(local["body"])) != body_digest:
                raise MirrorError("local mirror body is missing or diverges for key: " + action_key)
        live_entries = [action_key for action_key, entry in entries.items()
                        if entry["body_digest"] != TOMBSTONE_DIGEST]
        if any(action_key not in wanted for action_key in live_entries):
            raise MirrorError("mirror holds keys absent from the fixed view; refusing to mark synced")
        connection.execute(
            "UPDATE mirror_sessions SET phase=?, view_digest=?, key_count=? WHERE name=?",
            (PHASE_SYNCED, view_digest, key_count, session["name"]))

    def restart(self, session_name, target_revision=None):
        """Abandon the old read view and pin a fixed new view, then reconcile onto it.

        Reconciliation re-scans the whole new view: keys deleted or no longer matching the
        predicate are revoked, recreated keys are re-applied, and new keys sorting before
        the old pagination boundary are caught. A disconnect leaves the session rebasing and
        reopenable; repeating the call on the same target safely re-runs reconciliation.
        """
        with self.store.atomic(writable=True) as connection:
            session = self._session(connection, session_name)
            target = checked_revision(self.store, target_revision)
            if target < session["target_rev"]:
                raise Conflict("restart cannot move the read view backwards")
            if session["phase"] == PHASE_SYNCED:
                # A synced mirror may advance to a newer view; an equal target is a no-op.
                if target == session["target_rev"]:
                    return self._status_row(connection, session_name, 0, 0)
            floor = int(self.store.get("floor"))
            if target == session["target_rev"] and session["phase"] == PHASE_REBASING:
                revoked, applied, _ = self._reconcile(
                    connection, self._session(connection, session_name))
                self._finish_view(connection, self._session(connection, session_name))
                return self._status_row(connection, session_name, applied, revoked)
            connection.execute(
                "UPDATE mirror_sessions SET target_rev=?, source_floor=?, after_key=NULL, phase=?, "
                "view_digest=NULL, key_count=NULL, certificate=NULL WHERE name=?",
                (target, floor, PHASE_REBASING, session_name))
            session = self._session(connection, session_name)
            revoked, applied, _ = self._reconcile(connection, session)
            self._finish_view(connection, self._session(connection, session_name))
            return self._status_row(connection, session_name, applied, revoked)

    def certificate(self, session_name):
        """Issue a completion receipt that states exactly what the mirror covers."""
        with self.store.atomic(writable=True) as connection:
            session = self._session(connection, session_name)
            if session["phase"] != PHASE_SYNCED:
                raise MirrorError(
                    "cannot certify a partial mirror: the fixed view has not been fully verified")
            if session["certificate"] is not None:
                return loads(session["certificate"])
            wanted = self._source_view(connection, session)
            view_digest, key_count = self._view_digest(wanted)
            if view_digest != session["view_digest"]:
                raise MirrorError("mirror drifted from the certified view; restart before certifying")
            receipt = {"kind": "mirror_certificate", "session": session_name,
                       "source": session["source_id"],
                       "source_collection": session["source_collection"],
                       "collection": session["collection"],
                       "predicate": loads(session["predicate"]),
                       "predicate_fingerprint": session["predicate_fingerprint"],
                       "coverage": "complete", "revision": session["target_rev"],
                       "source_floor": session["source_floor"],
                       "key_count": key_count, "view_digest": view_digest,
                       "note": "covers the fixed read view only; reclaimed intermediate changes are not recoverable"}
            receipt["token"] = _token(self.store, receipt)
            connection.execute("UPDATE mirror_sessions SET certificate=? WHERE name=?",
                               (dumps(receipt), session_name))
            return receipt

    def verify(self, session_name):
        """Recompute both sides from actual tables and compare every mirrored fact."""
        with self.store.read() as connection:
            session = self._session(connection, session_name)
            wanted = self._source_view(connection, session)
            local_live = self._local_live(connection, session["collection"])
            entries = {row["key"]: row for row in connection.execute(
                "SELECT * FROM mirror_entries WHERE session=?", (session_name,)).fetchall()}
            issues = []
            for action_key, (source_rev, body_digest, _document, _expires) in wanted.items():
                entry = entries.pop(action_key, None)
                local = local_live.pop(action_key, None)
                if entry is None:
                    issues.append("missing mirrored key: " + action_key)
                    continue
                if entry["body_digest"] == TOMBSTONE_DIGEST:
                    issues.append("mirrored key is tombstoned but live in view: " + action_key)
                elif entry["source_rev"] != source_rev or entry["body_digest"] != body_digest:
                    issues.append("mirrored revision/digest differs for key: " + action_key)
                if local is None:
                    issues.append("local mirror body missing for key: " + action_key)
                elif digest(loads(local["body"])) != body_digest:
                    issues.append("local mirror body differs for key: " + action_key)
            for action_key, entry in entries.items():
                if entry["body_digest"] != TOMBSTONE_DIGEST:
                    issues.append("mirror bookkeeping holds a key absent from the view: " + action_key)
            for action_key in local_live:
                issues.append("local mirror holds an extra live key: " + action_key)
            view_digest, key_count = self._view_digest(wanted)
            matches_view = view_digest == session["view_digest"] and key_count == len(wanted)
            return {"ok": not issues and matches_view, "issues": issues,
                    "phase": session["phase"], "target_revision": session["target_rev"],
                    "expected_keys": len(wanted), "view_digest": view_digest,
                    "certified": session["certificate"] is not None}

    def handoff(self, session_name):
        """Return a signed, reopenable handoff token; nothing about the mirror changes."""
        with self.store.read() as connection:
            session = self._session(connection, session_name)
            payload = {"kind": "mirror_handoff", "database": self.store.get("database_id"),
                       "session": session_name, "source_collection": session["source_collection"],
                       "collection": session["collection"],
                       "target_revision": session["target_rev"], "phase": session["phase"],
                       "predicate_fingerprint": session["predicate_fingerprint"]}
            return {"token": _token(self.store, payload), "status": self._status(connection, session_name)}

    def reopen(self, token):
        """Reopen a session from a handoff token after a process restart or disconnect."""
        payload = _untoken(self.store, token)
        if payload.get("kind") != "mirror_handoff":
            raise MirrorError("token is not a mirror handoff")
        with self.store.read() as connection:
            session = self._session(connection, payload["session"])
            if session["source_collection"] != payload.get("source_collection") or \
               session["collection"] != payload.get("collection") or \
               session["target_rev"] != payload.get("target_revision") or \
               session["phase"] != payload.get("phase") or \
               session["predicate_fingerprint"] != payload.get("predicate_fingerprint"):
                raise MirrorError("handoff token is stale; the mirror moved on")
        return self.status(payload["session"])

    def abandon(self, session_name):
        """Permanently give up a mirror and remove all of its bookkeeping.

        The mirrored collection rows are left in place (ordinary versioned documents owned
        by the caller); only the session's confirmed-key tracking is deleted.
        """
        with self.store.atomic(writable=True) as connection:
            deleted = connection.execute(
                "DELETE FROM mirror_sessions WHERE name=?", (session_name,)).rowcount
            if not deleted:
                raise NotFound("unknown mirror session: " + session_name)
            connection.execute("DELETE FROM mirror_entries WHERE session=?", (session_name,))
        return {"abandoned": session_name}
