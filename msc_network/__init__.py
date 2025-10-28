"""
MSC Network v3.0 - Enterprise-Grade DeFi Platform
Blockchain de próxima generación con consenso híbrido, DeFi avanzado y escalabilidad
"""

# Core modules
from .core import (
    BlockchainConfig,
    TransactionType,
    ContractType,
    NetworkStatus,
    Account,
    TransactionReceipt,
    Log,
    StateProof,
    MerklePatriciaTrie,
    Transaction,
    Block,
    BlockHeader,
    MSCBlockchainV3
)

# Consensus modules
from .consensus import (
    VRF,
    ValidatorRegistry,
    HybridConsensus
)

# DeFi modules
from .defi import (
    DEXProtocol,
    LiquidityPool,
    LendingProtocol,
    Market,
    Position,
    OracleSystem
)

# Network modules
from .network import (
    P2PNetworkManager,
    DHTNode,
    EclipseAttackProtection,
    DiscoveryProtocol
)

# Virtual Machine modules
from .virtual_machine import (
    MSCVirtualMachine,
    MSCCompiler
)

# Governance modules
from .governance import (
    GovernanceSystem,
    Proposal,
    ProposalStatus,
    StakingSystem,
    ValidatorInfo,
    ValidatorStatus,
    UnbondingEntry
)

__version__ = "3.0.0"
__author__ = "MSC Network Team"

__all__ = [
    # Core
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
    'MSCBlockchainV3',
    
    # Consensus
    'VRF',
    'ValidatorRegistry',
    'HybridConsensus',
    
    # DeFi
    'DEXProtocol',
    'LiquidityPool',
    'LendingProtocol',
    'Market',
    'Position',
    'OracleSystem',
    
    # Network
    'P2PNetworkManager',
    'DHTNode',
    'EclipseAttackProtection',
    'DiscoveryProtocol',
    
    # Virtual Machine
    'MSCVirtualMachine',
    'MSCCompiler',
    
    # Governance
    'GovernanceSystem',
    'Proposal',
    'ProposalStatus',
    'StakingSystem',
    'ValidatorInfo',
    'ValidatorStatus',
    'UnbondingEntry'
]
