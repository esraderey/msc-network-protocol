"""
Estructuras de datos fundamentales del blockchain MSC
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

@dataclass
class Account:
    """Cuenta con estado completo"""
    address: str
    nonce: int = 0
    balance: int = 0  # en wei
    code_hash: Optional[str] = None  # para smart contracts
    storage_root: Optional[str] = None
    stake_amount: int = 0
    stake_block: Optional[int] = None
    delegated_stake: Dict[str, int] = field(default_factory=dict)

    def is_contract(self) -> bool:
        return self.code_hash is not None

@dataclass
class TransactionReceipt:
    """Recibo de transacción con información completa"""
    transaction_hash: str
    block_hash: str
    block_number: int
    from_address: str
    to_address: Optional[str]
    contract_address: Optional[str]  # si se creó un contrato
    gas_used: int
    cumulative_gas_used: int
    status: bool  # True = success, False = failed
    logs: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class Log:
    """Log de evento de smart contract"""
    address: str
    topics: List[str]
    data: str
    block_number: int
    transaction_hash: str
    transaction_index: int
    log_index: int
    removed: bool = False

@dataclass
class StateProof:
    """Prueba Merkle del estado"""
    account_proof: List[str]
    storage_proof: List[Dict[str, Any]]
