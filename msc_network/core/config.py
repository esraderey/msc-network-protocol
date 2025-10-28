"""
Configuración del blockchain MSC v3.0
"""

class BlockchainConfig:
    """Configuración enterprise-grade de MSC v3.0"""

    # Blockchain Core
    CHAIN_ID = 1337
    NETWORK_NAME = "MSC Mainnet"
    VERSION = "3.0.0"

    # Consensus Parameters
    CONSENSUS_TYPE = "HYBRID_POW_POS"  # Híbrido PoW/PoS
    INITIAL_DIFFICULTY = 4
    TARGET_BLOCK_TIME = 15  # 15 segundos
    DIFFICULTY_ADJUSTMENT_INTERVAL = 100  # bloques
    MAX_DIFFICULTY = 32
    MIN_DIFFICULTY = 1

    # PoS Parameters
    MIN_STAKE_AMOUNT = 1000.0  # MSC mínimo para staking
    STAKE_MATURITY_BLOCKS = 100  # Bloques antes de poder hacer stake
    ANNUAL_STAKING_REWARD = 0.05  # 5% anual
    SLASH_RATE = 0.1  # 10% slash por comportamiento malicioso

    # Block Parameters
    MAX_BLOCK_SIZE = 2_000_000  # 2MB
    MAX_TRANSACTIONS_PER_BLOCK = 500
    UNCLE_REWARD_PERCENT = 0.875  # 87.5% of block reward
    MAX_UNCLE_DEPTH = 7

    # Token Economics
    TOKEN_NAME = "Meta-cognitive Synthesis Coin"
    TOKEN_SYMBOL = "MSC"
    DECIMALS = 18
    INITIAL_SUPPLY = 100_000_000 * 10**18  # en wei

    # Rewards and Fees
    INITIAL_BLOCK_REWARD = 2.0 * 10**18  # 2 MSC
    HALVING_INTERVAL = 2_100_000  # ~4 años
    MIN_GAS_PRICE = 1_000_000_000  # 1 Gwei
    BASE_FEE_MAX_CHANGE_DENOMINATOR = 8
    ELASTICITY_MULTIPLIER = 2

    # Transaction Parameters
    MAX_TX_SIZE = 128_000  # 128KB
    TX_POOL_SIZE = 10_000
    TX_POOL_LIFETIME = 3600  # 1 hora
    MAX_NONCE_AHEAD = 1000

    # Network Parameters
    DEFAULT_PORT = 30303
    DEFAULT_RPC_PORT = 8545
    DEFAULT_WS_PORT = 8546
    MAX_PEERS = 100
    PEER_DISCOVERY_INTERVAL = 30
    SYNC_BATCH_SIZE = 100

    # State Management
    STATE_DB_PATH = "./state_db"
    BLOCKCHAIN_DB_PATH = "./blockchain.db"
    SNAPSHOT_INTERVAL = 10_000  # bloques
    PRUNING_ENABLED = True
    PRUNING_BLOCKS_TO_KEEP = 100_000

    # Smart Contract Parameters
    MAX_CODE_SIZE = 24_576  # 24KB
    MAX_STACK_DEPTH = 1024
    CALL_DEPTH_LIMIT = 1024
    CREATE_CONTRACT_GAS = 32_000

    # DeFi Parameters
    UNISWAP_FEE = 0.003  # 0.3%
    FLASH_LOAN_FEE = 0.0009  # 0.09%
    LIQUIDATION_THRESHOLD = 0.8  # 80%
    LIQUIDATION_BONUS = 0.05  # 5%
    ORACLE_UPDATE_INTERVAL = 60  # segundos

    # Security Parameters
    CHECKPOINT_INTERVAL = 1000  # bloques
    FINALITY_BLOCKS = 12
    FORK_CHOICE_RULE = "GHOST"  # Greedy Heaviest Observed SubTree

    # Performance
    CACHE_SIZE = 1000
    BLOOM_FILTER_SIZE = 1_000_000
    BLOOM_FILTER_ERROR_RATE = 0.001
