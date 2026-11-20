from .codec import digest, dumps, loads
from .errors import InvalidDocument, NotFound
from .mvcc import checked_revision, record, visible_rows
from .predicates import validate_predicate
from .transaction import WriteBatch


class Transfer:
    def __init__(self, store):
        self.store = store

    def export_lines(self, collection, revision=None):
        with self.store.read() as connection:
            revision = checked_revision(self.store, revision)
            if not connection.execute("SELECT 1 FROM collections WHERE name=?", (collection,)).fetchone():
                raise NotFound("unknown collection")
            output = []
            for row in visible_rows(connection, collection, revision):
                item = record(row)
                output.append(dumps({"key": item.key, "document": item.document, "expires_at": item.expires_at}))
            return {"revision": revision, "lines": output}

    def export_page(self, collection, limit=100, predicate=None, revision=None, cursor=None):
        """Export one identity-bearing, predicate-scoped page pinned to a fixed read view.

        The envelope names the source database, read revision, retained floor and predicate
        fingerprint, and gives every action its source revision plus a body digest. Cursors
        are signed tokens that re-pin the same read view; a view already below the retained
        floor is rejected (SnapshotTooOld) rather than silently moved to a newer view.
        """
        validate_predicate(predicate)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise InvalidDocument("page size must be between 1 and 1000")
        fingerprint = digest({"collection": collection, "predicate": predicate})
        with self.store.read() as connection:
            if not connection.execute("SELECT 1 FROM collections WHERE name=?", (collection,)).fetchone():
                raise NotFound("unknown collection")
            from .cursors import decode_cursor, encode_cursor
            from .predicates import matches
            after = None
            if cursor is not None:
                payload = decode_cursor(self.store, cursor)
                if payload.get("kind") != "mirror_page" or payload.get("query") != fingerprint:
                    raise InvalidDocument("cursor does not belong to this mirror export")
                if revision is not None and revision != payload.get("revision"):
                    raise InvalidDocument("cursor does not belong to the requested read revision")
                revision, after = payload.get("revision"), payload.get("after")
                if not isinstance(after, str):
                    raise InvalidDocument("cursor has no key boundary")
            revision = checked_revision(self.store, revision)
            actions = []
            for row in visible_rows(connection, collection, revision):
                if after is not None and row["key"] <= after:
                    continue
                item = record(row)
                if item is None or not matches(item.document, predicate):
                    continue
                body = item.document
                actions.append({"key": item.key, "op": "upsert", "revision": item.revision,
                                "body_digest": digest(body), "document": body,
                                "expires_at": item.expires_at})
                if len(actions) == limit:
                    break
            next_cursor = None
            if len(actions) == limit:
                last_key = actions[-1]["key"]
                has_more = False
                for row in visible_rows(connection, collection, revision):
                    if row["key"] <= last_key:
                        continue
                    candidate = record(row)
                    if candidate is not None and matches(candidate.document, predicate):
                        has_more = True
                        break
                if has_more:
                    next_cursor = encode_cursor(self.store, {"kind": "mirror_page",
                        "database": self.store.get("database_id"), "query": fingerprint,
                        "revision": revision, "after": last_key})
            return {"kind": "mirror_page", "source": self.store.get("database_id"),
                    "collection": collection, "predicate_fingerprint": fingerprint,
                    "revision": revision, "floor": int(self.store.get("floor")),
                    "actions": actions, "cursor": next_cursor}

    def import_lines(self, collection, lines, replace=False, request_key=None):
        if not isinstance(replace, bool):
            raise InvalidDocument("replace must be a boolean")
        batch = WriteBatch(self.store, request_key)
        count = 0
        for line in lines:
            count += 1
            if count > 10000 or not isinstance(line, str) or len(line.encode()) > 2 * 1024 * 1024:
                raise InvalidDocument("import exceeds bounded batch/line size")
            try:
                item = loads(line)
            except (ValueError, TypeError) as exc:
                raise InvalidDocument("invalid JSON at input line " + str(count)) from exc
            if not isinstance(item, dict) or set(item) - {"key", "document", "expires_at"} or not {"key", "document"}.issubset(item):
                raise InvalidDocument("line requires key and document, optional expires_at")
            batch.put(collection, item["key"], item["document"], expected=None if replace else 0,
                      expires_at=item.get("expires_at"))
        return batch.commit()
