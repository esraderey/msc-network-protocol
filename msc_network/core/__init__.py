"""
MSC Network Core Module
Módulo principal que contiene las estructuras de datos fundamentales del blockchain
"""

from .config import BlockchainConfig
from .types import TransactionType, ContractType, NetworkStatus
from .data_structures import Account, TransactionReceipt, Log, StateProof
from .merkle_trie import MerklePatriciaTrie
from .transaction import Transaction
from .block import Block, BlockHeader
from .blockchain import MSCBlockchainV3

__all__ = [
    'BlockchainConfig',
    'TransactionType', 
    'ContractType',
    'NetworkStatus',
    'Account',
    'TransactionReceipt',
    'Log',
    'StateProof',
    'MerklePatriciaTrie',
    'Transaction',
    'Block',
    'BlockHeader',
    'MSCBlockchainV3'
]
