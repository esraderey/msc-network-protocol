"""
Clase principal MSCBlockchainV3
"""

import asyncio
import inspect
import json
import time
import logging
from typing import List, Optional, Set
from collections import OrderedDict
from sortedcontainers import SortedList

from .config import BlockchainConfig
from .types import NetworkStatus
from .data_structures import Account
from .merkle_trie import MerklePatriciaTrie
from .block import Block, BlockHeader
from .transaction import Transaction
from ..utils import calculate_merkle_root, validate_address

# Importar otros módulos (se crearán después)
# from ..consensus import HybridConsensus
# from ..defi import DEXProtocol, LendingProtocol
# from ..governance import StakingSystem, GovernanceSystem
# from ..virtual_machine import MSCVirtualMachine

logger = logging.getLogger(__name__)

class MSCBlockchainV3:
    """Blockchain v3 con todas las características enterprise"""

    def __init__(self):
        # Core
        self.chain: List[Block] = []
        self.state_db = MerklePatriciaTrie(BlockchainConfig.STATE_DB_PATH)
        self.pending_transactions = SortedList(key=lambda tx: -tx.gas_price)
        self._pending_transaction_hashes = set()
        self.transaction_broadcaster = None

        # Consensus (se importará después)
        # self.consensus = HybridConsensus(self)

        # DeFi (se importará después)
        # self.dex = DEXProtocol("0x" + "0" * 40)
        # self.lending = LendingProtocol()
        # self.staking = StakingSystem(self)
        # self.governance = GovernanceSystem("0x" + "0" * 40)

        # Infrastructure (se importará después)
        # self.oracle_system = OracleSystem()
        # self.bridge = CrossChainBridge(BlockchainConfig.CHAIN_ID)
        # self.vm = MSCVirtualMachine(self.state_db)

        # Networking
        self.peers: Set[str] = set()
        self.sync_status = NetworkStatus.OFFLINE

        # Caches
        self.receipt_cache = OrderedDict()
        self.block_cache = OrderedDict()

        # Metrics
        self.total_transactions = 0
        self.total_gas_used = 0
        self._state_lock = asyncio.Lock()

        # Initialize
        self._init_genesis()
        self._start_services()

    def _init_genesis(self):
        """Inicializa bloque génesis"""
        genesis_header = BlockHeader(
            parent_hash='0x' + '0' * 64,
            uncle_hash='0x' + '0' * 64,
            coinbase='0x' + '0' * 40,
            state_root='0x' + '0' * 64,
            transactions_root='0x' + '0' * 64,
            receipts_root='0x' + '0' * 64,
            logs_bloom=b'\x00' * 256,
            difficulty=BlockchainConfig.INITIAL_DIFFICULTY,
            number=0,
            gas_limit=30_000_000,
            gas_used=0,
            timestamp=int(time.time()),
            extra_data=b'MSC Genesis Block v3.0',
            mix_hash='0x' + '0' * 64,
            nonce=0,
            base_fee_per_gas=BlockchainConfig.MIN_GAS_PRICE
        )

        genesis_block = Block(
            header=genesis_header,
            transactions=[]
        )

        self.chain.append(genesis_block)

        # Inicializar cuentas génesis
        self._init_genesis_accounts()
        genesis_block.header.state_root = self.state_db.root_hash or '0x' + '0' * 64
        genesis_block.hash = genesis_block.header.calculate_hash()

    def _init_genesis_accounts(self):
        """Inicializa cuentas con balance inicial"""
        genesis_allocations = [
            ("0x1234567890123456789012345678901234567890", 30_000_000 * 10**18),
            ("0x2345678901234567890123456789012345678901", 20_000_000 * 10**18),
            ("0x3456789012345678901234567890123456789012", 10_000_000 * 10**18),
        ]

        for address, balance in genesis_allocations:
            account = Account(address=address, balance=balance)
            self._save_account(account)

    def _save_account(self, account: Account):
        """Guarda cuenta en state DB"""
        from dataclasses import asdict
        account_key = f"account:{account.address}".encode()
        account_data = json.dumps(asdict(account)).encode()
        self.state_db.put(account_key, account_data)

    def _load_account(self, address: str) -> Optional[Account]:
        """Carga cuenta desde state DB"""
        account_key = f"account:{address}".encode()
        account_data = self.state_db.get(account_key)

        if account_data:
            account_dict = json.loads(account_data.decode())
            return Account(**account_dict)

        return None

    def get_balance(self, address: str) -> int:
        """Obtiene balance de una dirección (en wei)"""
        account = self._load_account(address)
        return account.balance if account else 0

    def get_nonce(self, address: str) -> int:
        """Obtiene nonce de una dirección"""
        account = self._load_account(address)
        return account.nonce if account else 0

    async def add_transaction(self, tx: Transaction, broadcast: bool = True) -> bool:
        """Añade transacción al pool"""
        try:
            if len(self.pending_transactions) >= BlockchainConfig.TX_POOL_SIZE:
                return False
            tx_hash = tx.calculate_hash()
            if tx_hash in self._pending_transaction_hashes:
                return False
            # Validar transacción
            if not await self._validate_transaction(tx):
                return False

            # Añadir al pool
            self.pending_transactions.add(tx)
            self._pending_transaction_hashes.add(tx_hash)
            # transactions_counter.inc()  # Se importará después

            # Propagar solo si el transporte de red fue configurado.
            if broadcast and callable(self.transaction_broadcaster):
                asyncio.create_task(self._broadcast_transaction(tx))

            return True

        except Exception as e:
            logger.error(f"Error adding transaction: {e}")
            return False

    async def _validate_transaction(self, tx: Transaction) -> bool:
        """Validación completa de transacción"""
        if not isinstance(tx.nonce, int) or tx.nonce < 0:
            raise ValueError("Invalid nonce")
        if not isinstance(tx.gas_price, int) or tx.gas_price < BlockchainConfig.MIN_GAS_PRICE:
            raise ValueError("Gas price below network minimum")
        if not isinstance(tx.gas_limit, int) or tx.gas_limit < 0:
            raise ValueError("Invalid gas limit")
        if not isinstance(tx.value, int) or tx.value < 0:
            raise ValueError("Invalid value")
        if tx.chain_id != BlockchainConfig.CHAIN_ID:
            raise ValueError("Wrong chain id")
        if tx.to is not None and not validate_address(tx.to):
            raise ValueError("Invalid recipient address")
        if len(tx.data) > BlockchainConfig.MAX_TX_SIZE:
            raise ValueError("Transaction data too large")

        # 1. Verificar firma
        sender = tx.sender()
        if not sender:
            raise ValueError("Invalid signature")

        # 2. Verificar cuenta
        account = self._load_account(sender)
        if not account:
            account = Account(address=sender)

        # 3. Verificar nonce
        if tx.nonce != account.nonce:
            if tx.nonce < account.nonce:
                raise ValueError(f"Invalid nonce: expected {account.nonce}, got {tx.nonce}")
            if tx.nonce > account.nonce + BlockchainConfig.MAX_NONCE_AHEAD:
                raise ValueError("Nonce too far ahead")

        # 4. Verificar balance para gas
        gas_cost = tx.gas_limit * tx.gas_price
        total_cost = gas_cost + tx.value

        if account.balance < total_cost:
            raise ValueError("Insufficient balance for gas + value")

        # 5. Verificar gas intrínseco
        if tx.gas_limit < tx.intrinsic_gas():
            raise ValueError("Gas limit below intrinsic gas")

        # 6. Verificar límites
        if tx.gas_limit > 30_000_000:
            raise ValueError("Gas limit too high")

        return True

    async def mine_block(self, miner_address: str) -> Optional[Block]:
        """Mina nuevo bloque con consenso híbrido"""
        # Por ahora implementación simplificada
        return await self._mine_simple_block(miner_address)

    async def _mine_simple_block(self, miner_address: str) -> Optional[Block]:
        """Aplica transacciones, actualiza estado y mina un bloque PoW."""
        if not validate_address(miner_address):
            raise ValueError("Invalid miner address")

        async with self._state_lock:
            parent = self.get_latest_block()
            candidates = self._select_transactions_for_block()
            transactions = []
            gas_used = 0

            for tx in candidates:
                try:
                    if not await self._validate_transaction(tx):
                        continue
                    sender = tx.sender()
                    account = self._load_account(sender)
                    gas = tx.intrinsic_gas()
                    fee = gas * tx.gas_price
                    account.balance -= tx.value + fee
                    account.nonce += 1
                    self._save_account(account)

                    if tx.to is not None:
                        recipient = self._load_account(tx.to) or Account(address=tx.to)
                        recipient.balance += tx.value
                        self._save_account(recipient)

                    miner = self._load_account(miner_address) or Account(address=miner_address)
                    miner.balance += fee
                    self._save_account(miner)
                    transactions.append(tx)
                    gas_used += gas
                except (ValueError, TypeError):
                    continue

            for tx in candidates:
                try:
                    self.pending_transactions.remove(tx)
                    self._pending_transaction_hashes.discard(tx.calculate_hash())
                except ValueError:
                    pass

            tx_root = calculate_merkle_root([tx.calculate_hash() for tx in transactions])
            header = BlockHeader(
                parent_hash=parent.hash,
                uncle_hash='0x' + '0' * 64,
                coinbase=miner_address,
                state_root=self.state_db.root_hash or '0x' + '0' * 64,
                transactions_root=tx_root,
                receipts_root=tx_root,
                logs_bloom=b'\x00' * 256,
                difficulty=BlockchainConfig.INITIAL_DIFFICULTY,
                number=parent.header.number + 1,
                gas_limit=30_000_000,
                gas_used=gas_used,
                timestamp=max(int(time.time()), parent.header.timestamp + 1),
                extra_data=b'',
                mix_hash='0x' + '0' * 64,
                nonce=0,
                base_fee_per_gas=BlockchainConfig.MIN_GAS_PRICE
            )

            block = Block(header=header, transactions=transactions)
            for nonce in range(2**32):
                block.header.nonce = nonce
                block.hash = block.header.calculate_hash()
                if block.verify_pow():
                    break
            else:
                raise RuntimeError("Unable to find a valid PoW nonce")

            self.chain.append(block)
            self.total_transactions += len(transactions)
            self.total_gas_used += gas_used
            return block

    def _select_transactions_for_block(self) -> List[Transaction]:
        """Selecciona transacciones para el siguiente bloque"""
        selected = []
        gas_used = 0
        
        for tx in self.pending_transactions:
            if len(selected) >= BlockchainConfig.MAX_TRANSACTIONS_PER_BLOCK:
                break
            if gas_used + tx.gas_limit > 30_000_000:
                break
            selected.append(tx)
            gas_used += tx.gas_limit
            
        return selected

    def get_latest_block(self) -> Block:
        """Obtiene el último bloque"""
        return self.chain[-1]

    def get_block_by_number(self, number: int) -> Optional[Block]:
        """Obtiene bloque por número"""
        if 0 <= number < len(self.chain):
            return self.chain[number]
        return None

    def get_block_by_hash(self, block_hash: str) -> Optional[Block]:
        """Obtiene bloque por hash"""
        for block in self.chain:
            if block.hash == block_hash:
                return block
        return None

    async def _broadcast_transaction(self, tx: Transaction):
        """Propaga transacción a peers"""
        if not callable(self.transaction_broadcaster):
            return
        message = {
            'type': 'transaction',
            'transaction': {
                'hash': tx.calculate_hash(),
                'nonce': tx.nonce,
                'gas_price': tx.gas_price,
                'gas_limit': tx.gas_limit,
                'to': tx.to,
                'value': tx.value,
                'data': tx.data.hex(),
                'v': tx.v,
                'r': tx.r,
                's': tx.s,
                'chain_id': tx.chain_id,
            },
        }
        result = self.transaction_broadcaster(message)
        if inspect.isawaitable(result):
            await result

    def _start_services(self):
        """Inicia servicios del blockchain"""
        logger.info("Starting MSC Blockchain v3.0 services")
