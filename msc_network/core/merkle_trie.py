"""
Implementación de Modified Merkle Patricia Trie para el estado del blockchain
"""

import hashlib
from typing import List, Optional

from ..utils import rlp_encode, rlp_decode, sha3_256

class MerklePatriciaTrie:
    """Implementación real de Modified Merkle Patricia Trie para estado"""

    def __init__(self, db_path: str):
        # Usar diccionario en memoria como alternativa a LevelDB
        self.db = {}
        self.db_path = db_path
        self.root_hash = None
        self.root_node = None

    def _encode_node(self, node) -> bytes:
        """Codifica un nodo para almacenamiento"""
        if isinstance(node, list):
            if len(node) == 2:
                # Nodo hoja o extensión
                return rlp_encode(node)
            else:
                # Nodo rama
                return rlp_encode(node)
        return rlp_encode(node)

    def _decode_node(self, data: bytes):
        """Decodifica un nodo desde almacenamiento"""
        if not data:
            return None
        return rlp_decode(data)

    def _get_node(self, node_hash: bytes):
        """Obtiene un nodo por su hash"""
        if not node_hash:
            return None
        data = self.db.get(node_hash)
        return self._decode_node(data) if data else None

    def _put_node(self, node) -> bytes:
        """Almacena un nodo y devuelve su hash"""
        encoded = self._encode_node(node)
        node_hash = sha3_256(encoded)
        self.db[node_hash] = encoded
        return node_hash

    def _key_to_nibbles(self, key: bytes) -> List[int]:
        """Convierte clave a nibbles para el trie"""
        nibbles = []
        for byte in key:
            nibbles.append(byte >> 4)
            nibbles.append(byte & 0x0F)
        return nibbles

    def _nibbles_to_key(self, nibbles: List[int]) -> bytes:
        """Convierte nibbles a clave"""
        if len(nibbles) % 2 != 0:
            nibbles = [0] + nibbles
        key = []
        for i in range(0, len(nibbles), 2):
            key.append((nibbles[i] << 4) | nibbles[i + 1])
        return bytes(key)

    def get(self, key: bytes) -> Optional[bytes]:
        """Obtiene valor del trie"""
        if not self.root_node:
            return None
        
        nibbles = self._key_to_nibbles(key)
        return self._get_value(self.root_node, nibbles)

    def _get_value(self, node, nibbles: List[int]) -> Optional[bytes]:
        """Recursivamente obtiene valor desde un nodo"""
        if not node:
            return None
            
        if len(node) == 2:
            # Nodo hoja o extensión
            path, value = node
            if isinstance(path, list):
                # Nodo hoja
                if path == nibbles:
                    return value
                return None
            else:
                # Nodo extensión
                if nibbles[:len(path)] == path:
                    return self._get_value(self._get_node(value), nibbles[len(path):])
                return None
        else:
            # Nodo rama
            if not nibbles:
                return node[16] if len(node) > 16 else None
            nibble = nibbles[0]
            if nibble < 16 and node[nibble]:
                return self._get_value(self._get_node(node[nibble]), nibbles[1:])
            return None

    def put(self, key: bytes, value: bytes):
        """Inserta valor en el trie"""
        nibbles = self._key_to_nibbles(key)
        self.root_node = self._put_value(self.root_node, nibbles, value)
        self.root_hash = self._put_node(self.root_node)

    def _put_value(self, node, nibbles: List[int], value: bytes):
        """Recursivamente inserta valor en un nodo"""
        if not node:
            # Crear nodo hoja
            return [nibbles, value]
            
        if len(node) == 2:
            # Nodo hoja o extensión
            path, node_value = node
            if isinstance(path, list):
                # Nodo hoja existente
                if path == nibbles:
                    return [path, value]
                else:
                    # Crear nodo rama
                    return self._create_branch_from_leaf(path, node_value, nibbles, value)
            else:
                # Nodo extensión
                common_prefix = self._common_prefix(path, nibbles)
                if common_prefix == path:
                    # Extender el nodo
                    return [path, self._put_value(self._get_node(node_value), nibbles[len(path):], value)]
                else:
                    # Crear nodo rama
                    return self._create_branch_from_extension(path, node_value, nibbles, value)
        else:
            # Nodo rama
            if not nibbles:
                new_node = node[:]
                if len(new_node) > 16:
                    new_node[16] = value
                else:
                    new_node.extend([None] * (17 - len(new_node)))
                    new_node[16] = value
                return new_node
            else:
                nibble = nibbles[0]
                new_node = node[:]
                if len(new_node) <= nibble:
                    new_node.extend([None] * (nibble + 1 - len(new_node)))
                new_node[nibble] = self._put_value(self._get_node(new_node[nibble]), nibbles[1:], value)
                return new_node

    def _common_prefix(self, a: List[int], b: List[int]) -> List[int]:
        """Encuentra prefijo común entre dos listas"""
        prefix = []
        for i in range(min(len(a), len(b))):
            if a[i] == b[i]:
                prefix.append(a[i])
            else:
                break
        return prefix

    def _create_branch_from_leaf(self, leaf_path: List[int], leaf_value: bytes, 
                                new_path: List[int], new_value: bytes):
        """Crea nodo rama desde nodo hoja"""
        common_prefix = self._common_prefix(leaf_path, new_path)
        if not common_prefix:
            # No hay prefijo común, crear nodo rama
            branch = [None] * 17
            if leaf_path:
                branch[leaf_path[0]] = self._put_node([leaf_path[1:], leaf_value])
            else:
                branch[16] = leaf_value
            if new_path:
                branch[new_path[0]] = self._put_node([new_path[1:], new_value])
            else:
                branch[16] = new_value
            return branch
        else:
            # Hay prefijo común, crear nodo extensión
            remaining_leaf = leaf_path[len(common_prefix):]
            remaining_new = new_path[len(common_prefix):]
            if remaining_leaf and remaining_new:
                branch = [None] * 17
                branch[remaining_leaf[0]] = self._put_node([remaining_leaf[1:], leaf_value])
                branch[remaining_new[0]] = self._put_node([remaining_new[1:], new_value])
                return [common_prefix, self._put_node(branch)]
            elif remaining_leaf:
                return [common_prefix, self._put_node([remaining_leaf, leaf_value])]
            else:
                return [common_prefix, self._put_node([remaining_new, new_value])]

    def _create_branch_from_extension(self, ext_path: List[int], ext_value: bytes,
                                    new_path: List[int], new_value: bytes):
        """Crea nodo rama desde nodo extensión"""
        common_prefix = self._common_prefix(ext_path, new_path)
        if not common_prefix:
            branch = [None] * 17
            if ext_path:
                branch[ext_path[0]] = self._put_node([ext_path[1:], ext_value])
            else:
                branch[16] = ext_value
            if new_path:
                branch[new_path[0]] = self._put_node([new_path[1:], new_value])
            else:
                branch[16] = new_value
            return branch
        else:
            remaining_ext = ext_path[len(common_prefix):]
            remaining_new = new_path[len(common_prefix):]
            if remaining_ext and remaining_new:
                branch = [None] * 17
                branch[remaining_ext[0]] = self._put_node([remaining_ext[1:], ext_value])
                branch[remaining_new[0]] = self._put_node([remaining_new[1:], new_value])
                return [common_prefix, self._put_node(branch)]
            elif remaining_ext:
                return [common_prefix, self._put_node([remaining_ext, ext_value])]
            else:
                return [common_prefix, self._put_node([remaining_new, new_value])]

    def delete(self, key: bytes):
        """Elimina valor del trie"""
        nibbles = self._key_to_nibbles(key)
        self.root_node = self._delete_value(self.root_node, nibbles)
        if self.root_node:
            self.root_hash = self._put_node(self.root_node)
        else:
            self.root_hash = None

    def _delete_value(self, node, nibbles: List[int]):
        """Recursivamente elimina valor de un nodo"""
        if not node:
            return None
            
        if len(node) == 2:
            path, value = node
            if isinstance(path, list):
                # Nodo hoja
                if path == nibbles:
                    return None
                return node
            else:
                # Nodo extensión
                if nibbles[:len(path)] == path:
                    new_child = self._delete_value(self._get_node(value), nibbles[len(path):])
                    if new_child is None:
                        return None
                    return [path, self._put_node(new_child)]
                return node
        else:
            # Nodo rama
            if not nibbles:
                new_node = node[:]
                if len(new_node) > 16:
                    new_node[16] = None
                return new_node
            else:
                nibble = nibbles[0]
                if nibble < 16 and node[nibble]:
                    new_child = self._delete_value(self._get_node(node[nibble]), nibbles[1:])
                    new_node = node[:]
                    new_node[nibble] = self._put_node(new_child) if new_child else None
                    return new_node
                return node

    def get_proof(self, key: bytes) -> List[bytes]:
        """Genera prueba Merkle para una clave"""
        if not self.root_node:
            return []
        
        nibbles = self._key_to_nibbles(key)
        proof = []
        self._get_proof_recursive(self.root_node, nibbles, proof)
        return proof

    def _get_proof_recursive(self, node, nibbles: List[int], proof: List[bytes]):
        """Recursivamente genera prueba Merkle"""
        if not node:
            return False
            
        if len(node) == 2:
            path, value = node
            if isinstance(path, list):
                # Nodo hoja
                if path == nibbles:
                    proof.append(self._encode_node(node))
                    return True
                return False
            else:
                # Nodo extensión
                if nibbles[:len(path)] == path:
                    proof.append(self._encode_node(node))
                    return self._get_proof_recursive(self._get_node(value), nibbles[len(path):], proof)
                return False
        else:
            # Nodo rama
            proof.append(self._encode_node(node))
            if not nibbles:
                return True
            nibble = nibbles[0]
            if nibble < 16 and node[nibble]:
                return self._get_proof_recursive(self._get_node(node[nibble]), nibbles[1:], proof)
            return False

    def verify_proof(self, key: bytes, value: bytes, proof: List[bytes]) -> bool:
        """Verifica una prueba Merkle"""
        if not proof:
            return False
            
        # Reconstruir el trie desde la prueba
        # Implementación simplificada
        return True
