"""
Clases Block y BlockHeader del blockchain MSC
"""

import hashlib
from dataclasses import dataclass, field
from typing import List, Optional

from .transaction import Transaction

@dataclass
class BlockHeader:
    """Header del bloque con campos completos"""
    parent_hash: str
    uncle_hash: str
    coinbase: str  # Dirección del minero/validador
    state_root: str
    transactions_root: str
    receipts_root: str
    logs_bloom: bytes
    difficulty: int
    number: int
    gas_limit: int
    gas_used: int
    timestamp: int
    extra_data: bytes
    mix_hash: str
    nonce: int
    base_fee_per_gas: Optional[int] = None

    def calculate_hash(self) -> str:
        """Calcula el hash del header"""
        header_data = f"{self.parent_hash}{self.state_root}{self.transactions_root}" \
                     f"{self.receipts_root}{self.number}{self.timestamp}{self.nonce}"
        return '0x' + hashlib.sha256(header_data.encode()).hexdigest()

@dataclass
class Block:
    """Bloque v3 con soporte completo"""
    header: BlockHeader
    transactions: List[Transaction]
    uncles: List[BlockHeader] = field(default_factory=list)

    # Campos calculados
    hash: Optional[str] = None
    total_difficulty: Optional[int] = None
    size: Optional[int] = None

    def __post_init__(self):
        if not self.hash:
            self.hash = self.header.calculate_hash()

    def calculate_transactions_root(self) -> str:
        """Calcula Merkle root de transacciones"""
        if not self.transactions:
            return '0x' + '0' * 64

        leaves = [tx.calculate_hash() for tx in self.transactions]
        return self._calculate_merkle_root(leaves)

    def _calculate_merkle_root(self, leaves: List[str]) -> str:
        """Calcula Merkle root recursivamente"""
        if len(leaves) == 1:
            return leaves[0]

        if len(leaves) % 2 == 1:
            leaves.append(leaves[-1])

        next_level = []
        for i in range(0, len(leaves), 2):
            combined = leaves[i] + leaves[i + 1]
            next_hash = '0x' + hashlib.sha256(combined.encode()).hexdigest()
            next_level.append(next_hash)

        return self._calculate_merkle_root(next_level)

    def verify_pow(self) -> bool:
        """Verifica Proof of Work"""
        target = 2 ** (256 - self.header.difficulty)
        block_hash = int(self.hash[2:], 16)
        return block_hash < target
