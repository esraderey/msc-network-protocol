"""
Tipos y enumeraciones del blockchain MSC
"""

from enum import Enum

class TransactionType(Enum):
    """Tipos de transacción soportados"""
    TRANSFER = "transfer"
    CONTRACT_CREATION = "contract_creation"
    CONTRACT_CALL = "contract_call"
    STAKE = "stake"
    UNSTAKE = "unstake"
    VOTE = "vote"
    CROSS_CHAIN = "cross_chain"
    FLASH_LOAN = "flash_loan"

class ContractType(Enum):
    """Tipos de smart contracts"""
    ERC20 = "erc20"
    ERC721 = "erc721"
    ERC1155 = "erc1155"
    DEX = "dex"
    LENDING = "lending"
    STAKING = "staking"
    GOVERNANCE = "governance"
    ORACLE = "oracle"
    BRIDGE = "bridge"
    VAULT = "vault"

class NetworkStatus(Enum):
    """Estado de la red"""
    SYNCING = "syncing"
    SYNCED = "synced"
    OFFLINE = "offline"
    FORKED = "forked"
