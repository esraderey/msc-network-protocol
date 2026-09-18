"""Persistent authenticated key/value trie used for blockchain state."""

import base64
import json
from pathlib import Path
from typing import Dict, List, Optional

from ..utils import rlp_encode, rlp_decode, sha3_256


class MerklePatriciaTrie:
    """Deterministic authenticated store with persistent state.

    The canonical state encoding is the RLP list of sorted ``[key, value]``
    pairs. It is intentionally small and self-contained, while retaining the
    existing trie API used by the node.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._persistence_path = Path(f"{db_path}.json")
        self.data: Dict[bytes, bytes] = {}
        self.db: Dict[bytes, bytes] = {}
        self.root_hash: Optional[str] = None
        self.root_node = None
        self._load()

    def _canonical_entries(self):
        return [[key, value] for key, value in sorted(self.data.items())]

    def _encode_node(self, node) -> bytes:
        return rlp_encode(node)

    def _decode_node(self, encoded: bytes):
        return rlp_decode(encoded) if encoded else None

    def _put_node(self, node) -> bytes:
        encoded = self._encode_node(node)
        node_hash = sha3_256(encoded)
        self.db[node_hash] = encoded
        return node_hash

    def _get_node(self, node_hash: bytes):
        encoded = self.db.get(node_hash)
        return self._decode_node(encoded) if encoded else None

    def get(self, key: bytes) -> Optional[bytes]:
        if not isinstance(key, bytes):
            raise TypeError("Trie keys must be bytes")
        return self.data.get(key)

    def put(self, key: bytes, value: bytes):
        if not isinstance(key, bytes) or not isinstance(value, bytes):
            raise TypeError("Trie keys and values must be bytes")
        self.data[key] = value
        self._recompute_root()

    def delete(self, key: bytes):
        if not isinstance(key, bytes):
            raise TypeError("Trie keys must be bytes")
        self.data.pop(key, None)
        self._recompute_root()

    def _recompute_root(self):
        encoded = rlp_encode(self._canonical_entries())
        self.root_hash = "0x" + sha3_256(encoded).hex() if self.data else None
        self.root_node = self._canonical_entries()
        self.db.clear()
        if self.root_node:
            self._put_node(self.root_node)
        self._persist()

    def get_proof(self, key: bytes) -> List[bytes]:
        """Return a self-contained proof bound to the current root."""
        payload = [self.root_hash or "", self._canonical_entries()]
        return [b"MSC_TRIE_PROOF_V1", rlp_encode(payload)]

    def verify_proof(self, key: bytes, value: bytes, proof: List[bytes]) -> bool:
        try:
            if not isinstance(key, bytes) or not isinstance(value, bytes):
                return False
            if len(proof) != 2 or proof[0] != b"MSC_TRIE_PROOF_V1":
                return False
            expected_root, entries = rlp_decode(proof[1])
            if expected_root.decode("ascii") != (self.root_hash or ""):
                return False
            normalized = [(entry[0], entry[1]) for entry in entries]
            if (key, value) not in normalized:
                return False
            encoded = rlp_encode([[k, v] for k, v in sorted(normalized)])
            actual_root = "0x" + sha3_256(encoded).hex() if normalized else None
            return actual_root == self.root_hash
        except (TypeError, ValueError, IndexError, UnicodeDecodeError):
            return False

    def _persist(self):
        self._persistence_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "data": {key.hex(): base64.b64encode(value).decode()
                     for key, value in self.data.items()},
            "root_hash": self.root_hash,
        }
        temporary = self._persistence_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        temporary.replace(self._persistence_path)

    def _load(self):
        if not self._persistence_path.exists():
            return
        try:
            payload = json.loads(self._persistence_path.read_text(encoding="utf-8"))
            self.data = {
                bytes.fromhex(key): base64.b64decode(value)
                for key, value in payload.get("data", {}).items()
            }
            self._recompute_root()
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"Corrupt trie database: {self._persistence_path}") from exc
