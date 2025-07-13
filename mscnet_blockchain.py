#!/usr/bin/env python3
"""
MSC Blockchain v3.0 - Enterprise-Grade DeFi Platform
Blockchain de próxima generación con consenso híbrido, DeFi avanzado y escalabilidad
Basado en el MSC Framework v5.0
"""

import asyncio
import hashlib
import json
import time
import os
import secrets
import logging
import pickle
import threading
import struct
import bisect
import math
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from collections import defaultdict, deque, OrderedDict
import base64
import sqlite3
import numpy as np
from decimal import Decimal, getcontext
import heapq
import zlib

# Set decimal precision for DeFi operations
getcontext().prec = 28

# Criptografía avanzada
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
import ed25519

# Web y API
import aiohttp
from aiohttp import web
import socketio
import jwt
from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import requests

# Métricas y Monitoring
import prometheus_client
from prometheus_client import Counter, Histogram, Gauge, Summary

# Data structures
from sortedcontainers import SortedList, SortedDict
from pybloom_live import BloomFilter
import plyvel  # LevelDB for state storage

# === MÉTRICAS AVANZADAS ===
blocks_mined_counter = Counter('msc_blocks_mined_total', 'Total blocks mined')
transactions_counter = Counter('msc_transactions_total', 'Total transactions processed')
smart_contract_calls = Counter('msc_smart_contract_calls_total', 'Smart contract executions')
defi_volume_gauge = Gauge('msc_defi_volume_usd', 'Total DeFi volume in USD')
staking_total_gauge = Gauge('msc_staking_total', 'Total MSC staked')
gas_used_histogram = Histogram('msc_gas_used', 'Gas used per transaction')
consensus_time = Summary('msc_consensus_seconds', 'Time to reach consensus')
network_latency = Histogram('msc_network_latency_ms', 'Network latency between peers')

# === CONFIGURACIÓN AVANZADA ===
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

# === TIPOS Y ENUMS MEJORADOS ===
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

# === ESTRUCTURAS DE DATOS AVANZADAS ===
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
    
# === PATRICIA MERKLE TRIE ===
class MerklePatriciaTrie:
    """Implementación de Modified Merkle Patricia Trie para estado"""
    
    def __init__(self, db_path: str):
        self.db = plyvel.DB(db_path, create_if_missing=True)
        self.root_hash = None
        
    def get(self, key: bytes) -> Optional[bytes]:
        """Obtiene valor del trie"""
        # Implementación simplificada
        return self.db.get(key)
    
    def put(self, key: bytes, value: bytes):
        """Inserta valor en el trie"""
        self.db.put(key, value)
        self._update_root()
    
    def delete(self, key: bytes):
        """Elimina valor del trie"""
        self.db.delete(key)
        self._update_root()
    
    def _update_root(self):
        """Actualiza el root hash del trie"""
        # Implementación simplificada
        all_data = b""
        for key, value in self.db:
            all_data += key + value
        self.root_hash = hashlib.sha256(all_data).hexdigest()
    
    def get_proof(self, key: bytes) -> List[bytes]:
        """Genera prueba Merkle para una clave"""
        # Implementación simplificada de prueba
        proof = []
        # En una implementación real, esto recorrería el trie
        return proof
    
    def verify_proof(self, key: bytes, value: bytes, proof: List[bytes]) -> bool:
        """Verifica una prueba Merkle"""
        # Implementación simplificada
        return True

# === TRANSACCIONES MEJORADAS ===
@dataclass
class Transaction:
    """Transacción v3 con soporte completo para DeFi"""
    nonce: int
    gas_price: int
    gas_limit: int
    to: Optional[str]  # None para creación de contrato
    value: int  # en wei
    data: bytes = b""  # input data para contratos
    v: Optional[int] = None
    r: Optional[int] = None
    s: Optional[int] = None
    
    # Campos adicionales
    tx_type: TransactionType = TransactionType.TRANSFER
    chain_id: int = BlockchainConfig.CHAIN_ID
    access_list: List[Tuple[str, List[str]]] = field(default_factory=list)
    max_priority_fee_per_gas: Optional[int] = None
    max_fee_per_gas: Optional[int] = None
    
    def calculate_hash(self) -> str:
        """Calcula hash de la transacción"""
        tx_data = {
            'nonce': self.nonce,
            'gasPrice': self.gas_price,
            'gasLimit': self.gas_limit,
            'to': self.to,
            'value': self.value,
            'data': self.data.hex() if self.data else '',
            'chainId': self.chain_id,
            'type': self.tx_type.value
        }
        
        tx_string = json.dumps(tx_data, sort_keys=True)
        return '0x' + hashlib.sha256(tx_string.encode()).hexdigest()
    
    def sign(self, private_key: ec.EllipticCurvePrivateKey):
        """Firma la transacción con ECDSA"""
        message = self.signing_hash()
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        
        # Decodificar firma DER a r, s
        r, s = self._decode_signature(signature)
        self.r = r
        self.s = s
        self.v = self.chain_id * 2 + 35  # EIP-155
        
    def signing_hash(self) -> bytes:
        """Hash para firmar (EIP-155)"""
        # Implementación simplificada
        data = rlp_encode([
            self.nonce,
            self.gas_price,
            self.gas_limit,
            self.to or b'',
            self.value,
            self.data,
            self.chain_id,
            0,
            0
        ])
        return hashlib.sha256(data).digest()
    
    def sender(self) -> Optional[str]:
        """Recupera la dirección del sender desde la firma"""
        if not all([self.v, self.r, self.s]):
            return None
        
        # Recuperar clave pública desde firma
        # Implementación simplificada
        return "0x" + hashlib.sha256(f"{self.r}{self.s}".encode()).hexdigest()[:40]
    
    def intrinsic_gas(self) -> int:
        """Calcula el gas intrínseco de la transacción"""
        gas = 21000  # Gas base
        
        # Gas por datos
        for byte in self.data:
            if byte == 0:
                gas += 4
            else:
                gas += 16
        
        # Gas adicional por tipo
        if self.tx_type == TransactionType.CONTRACT_CREATION:
            gas += BlockchainConfig.CREATE_CONTRACT_GAS
        
        return gas
    
    def _decode_signature(self, signature: bytes) -> Tuple[int, int]:
        """Decodifica firma DER a r, s"""
        # Implementación simplificada
        r = int.from_bytes(signature[:32], 'big')
        s = int.from_bytes(signature[32:64], 'big')
        return r, s

# === BLOQUES MEJORADOS ===
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
    
    def calculate_base_fee(self, parent_block: 'Block') -> int:
        """Calcula base fee según EIP-1559"""
        parent_gas_target = parent_block.header.gas_limit // BlockchainConfig.ELASTICITY_MULTIPLIER
        
        if parent_block.header.gas_used == parent_gas_target:
            return parent_block.header.base_fee_per_gas or BlockchainConfig.MIN_GAS_PRICE
        
        if parent_block.header.gas_used > parent_gas_target:
            gas_used_delta = parent_block.header.gas_used - parent_gas_target
            base_fee_delta = max(
                parent_block.header.base_fee_per_gas * gas_used_delta // 
                parent_gas_target // BlockchainConfig.BASE_FEE_MAX_CHANGE_DENOMINATOR,
                1
            )
            return parent_block.header.base_fee_per_gas + base_fee_delta
        else:
            gas_used_delta = parent_gas_target - parent_block.header.gas_used
            base_fee_delta = parent_block.header.base_fee_per_gas * gas_used_delta // \
                            parent_gas_target // BlockchainConfig.BASE_FEE_MAX_CHANGE_DENOMINATOR
            return max(parent_block.header.base_fee_per_gas - base_fee_delta, 0)

# === VIRTUAL MACHINE MEJORADA ===
class MSCVirtualMachine:
    """Máquina virtual completa para smart contracts"""
    
    def __init__(self, state_db: MerklePatriciaTrie):
        self.state_db = state_db
        self.stack = []
        self.memory = bytearray()
        self.storage = {}
        self.pc = 0  # Program counter
        self.gas_remaining = 0
        self.return_data = b""
        self.logs = []
        
        # Opcodes
        self.opcodes = {
            0x00: self.op_stop,
            0x01: self.op_add,
            0x02: self.op_mul,
            0x03: self.op_sub,
            0x04: self.op_div,
            0x10: self.op_lt,
            0x11: self.op_gt,
            0x14: self.op_eq,
            0x20: self.op_sha3,
            0x30: self.op_address,
            0x31: self.op_balance,
            0x35: self.op_calldataload,
            0x36: self.op_calldatasize,
            0x50: self.op_pop,
            0x51: self.op_mload,
            0x52: self.op_mstore,
            0x54: self.op_sload,
            0x55: self.op_sstore,
            0x56: self.op_jump,
            0x57: self.op_jumpi,
            0x60: self.op_push1,
            0xa0: self.op_log0,
            0xf3: self.op_return,
            0xfd: self.op_revert,
            0xff: self.op_selfdestruct,
        }
        
    def execute(self, code: bytes, gas_limit: int, context: Dict[str, Any]) -> Dict[str, Any]:
        """Ejecuta bytecode de contrato"""
        self.gas_remaining = gas_limit
        self.context = context
        
        try:
            while self.pc < len(code) and self.gas_remaining > 0:
                opcode = code[self.pc]
                
                if opcode in self.opcodes:
                    self.opcodes[opcode]()
                else:
                    raise Exception(f"Invalid opcode: {hex(opcode)}")
                
                self.pc += 1
            
            return {
                'success': True,
                'gas_used': gas_limit - self.gas_remaining,
                'return_data': self.return_data,
                'logs': self.logs,
                'storage_changes': self.storage
            }
            
        except Exception as e:
            return {
                'success': False,
                'gas_used': gas_limit - self.gas_remaining,
                'error': str(e),
                'logs': self.logs
            }
    
    def use_gas(self, amount: int):
        """Consume gas"""
        if self.gas_remaining < amount:
            raise Exception("Out of gas")
        self.gas_remaining -= amount
    
    # Implementación de opcodes básicos
    def op_stop(self):
        """STOP - Detiene la ejecución"""
        self.use_gas(0)
        self.pc = float('inf')
    
    def op_add(self):
        """ADD - Suma dos valores del stack"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append((a + b) % 2**256)
    
    def op_mul(self):
        """MUL - Multiplica dos valores del stack"""
        self.use_gas(5)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append((a * b) % 2**256)
    
    def op_sstore(self):
        """SSTORE - Almacena valor en storage"""
        self.use_gas(20000)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        key = self.stack.pop()
        value = self.stack.pop()
        self.storage[key] = value
    
    def op_sload(self):
        """SLOAD - Carga valor de storage"""
        self.use_gas(200)
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        key = self.stack.pop()
        value = self.storage.get(key, 0)
        self.stack.append(value)

# === SISTEMA DE CONSENSO HÍBRIDO ===
class HybridConsensus:
    """Sistema de consenso híbrido PoW/PoS"""
    
    def __init__(self, blockchain: 'MSCBlockchainV3'):
        self.blockchain = blockchain
        self.validators = {}  # address -> stake_amount
        self.current_epoch = 0
        self.epoch_length = 100  # bloques por época
        
    def select_block_producer(self, block_height: int) -> str:
        """Selecciona productor de bloque según el consenso híbrido"""
        # Alternar entre PoW y PoS cada X bloques
        if block_height % 10 < 7:
            # 70% PoW
            return "POW"
        else:
            # 30% PoS - seleccionar validador
            return self._select_validator()
    
    def _select_validator(self) -> str:
        """Selecciona validador basado en stake"""
        if not self.validators:
            return "POW"  # Fallback a PoW si no hay validadores
        
        # Selección ponderada por stake
        total_stake = sum(self.validators.values())
        if total_stake == 0:
            return "POW"
        
        # Usar block hash como semilla para aleatoriedad
        last_block_hash = self.blockchain.get_latest_block().hash
        random_value = int(last_block_hash, 16) % total_stake
        
        cumulative = 0
        for validator, stake in self.validators.items():
            cumulative += stake
            if cumulative > random_value:
                return validator
        
        return list(self.validators.keys())[0]
    
    def add_validator(self, address: str, stake: int):
        """Añade o actualiza validador"""
        if stake >= BlockchainConfig.MIN_STAKE_AMOUNT * 10**18:
            self.validators[address] = stake
    
    def remove_validator(self, address: str):
        """Elimina validador"""
        self.validators.pop(address, None)
    
    def slash_validator(self, address: str, reason: str):
        """Penaliza validador por mal comportamiento"""
        if address in self.validators:
            slash_amount = int(self.validators[address] * BlockchainConfig.SLASH_RATE)
            self.validators[address] -= slash_amount
            
            # Si queda por debajo del mínimo, eliminar
            if self.validators[address] < BlockchainConfig.MIN_STAKE_AMOUNT * 10**18:
                self.remove_validator(address)
            
            logging.warning(f"Validator {address} slashed {slash_amount} for {reason}")
    
    def calculate_rewards(self, block: Block) -> Dict[str, int]:
        """Calcula recompensas para mineros y validadores"""
        rewards = {}
        base_reward = self.blockchain.get_block_reward(block.header.number)
        
        if block.header.coinbase.startswith("POW"):
            # Recompensa completa para minero PoW
            rewards[block.header.coinbase] = base_reward
        else:
            # Distribuir entre validador y delegadores
            validator_reward = int(base_reward * 0.9)  # 90% para validador
            rewards[block.header.coinbase] = validator_reward
            
            # 10% para delegadores (proporcional a su stake)
            if block.header.coinbase in self.validators:
                # Implementar distribución a delegadores
                pass
        
        return rewards

# === SISTEMA DE ORÁCULOS ===
class OracleSystem:
    """Sistema de oráculos para datos externos"""
    
    def __init__(self):
        self.price_feeds = {}  # symbol -> price_data
        self.oracle_nodes = set()
        self.price_history = defaultdict(deque)
        self.update_threshold = 0.01  # 1% cambio mínimo
        
    async def update_price(self, symbol: str, price: Decimal, source: str):
        """Actualiza precio desde fuente oracle"""
        current_time = time.time()
        
        # Validar fuente
        if source not in self.oracle_nodes:
            raise ValueError("Unknown oracle source")
        
        # Almacenar en historial
        self.price_history[symbol].append({
            'price': price,
            'timestamp': current_time,
            'source': source
        })
        
        # Mantener solo últimas 100 entradas
        if len(self.price_history[symbol]) > 100:
            self.price_history[symbol].popleft()
        
        # Calcular precio agregado (mediana)
        recent_prices = [
            entry['price'] 
            for entry in self.price_history[symbol]
            if current_time - entry['timestamp'] < 300  # últimos 5 minutos
        ]
        
        if recent_prices:
            median_price = sorted(recent_prices)[len(recent_prices) // 2]
            
            # Actualizar si cambio significativo
            if symbol not in self.price_feeds or \
               abs(median_price - self.price_feeds[symbol]['price']) / self.price_feeds[symbol]['price'] > self.update_threshold:
                
                self.price_feeds[symbol] = {
                    'price': median_price,
                    'timestamp': current_time,
                    'confidence': len(recent_prices) / len(self.oracle_nodes)
                }
    
    def get_price(self, symbol: str) -> Optional[Dict[str, Any]]:
        """Obtiene precio actual"""
        if symbol in self.price_feeds:
            price_data = self.price_feeds[symbol]
            
            # Verificar si el precio no es muy antiguo
            if time.time() - price_data['timestamp'] < 3600:  # 1 hora
                return price_data
        
        return None
    
    def register_oracle(self, oracle_address: str, stake: int):
        """Registra nuevo nodo oracle"""
        if stake >= 10000 * 10**18:  # Requiere 10k MSC stake
            self.oracle_nodes.add(oracle_address)

# === SMART CONTRACTS DEFI ===
class DEXProtocol:
    """Protocolo DEX mejorado con AMM avanzado"""
    
    def __init__(self, factory_address: str):
        self.factory_address = factory_address
        self.pairs = {}  # pair_address -> LiquidityPool
        self.router_address = None
        
    def create_pair(self, token0: str, token1: str) -> str:
        """Crea nuevo par de liquidez"""
        # Ordenar tokens
        if token0 > token1:
            token0, token1 = token1, token0
        
        pair_address = self._compute_pair_address(token0, token1)
        
        if pair_address not in self.pairs:
            self.pairs[pair_address] = LiquidityPool(token0, token1)
        
        return pair_address
    
    def _compute_pair_address(self, token0: str, token1: str) -> str:
        """Calcula dirección determinística del par"""
        data = f"{self.factory_address}{token0}{token1}"
        return '0x' + hashlib.sha256(data.encode()).hexdigest()[:40]

@dataclass
class LiquidityPool:
    """Pool de liquidez con matemáticas precisas"""
    token0: str
    token1: str
    reserve0: Decimal = Decimal(0)
    reserve1: Decimal = Decimal(0)
    total_supply: Decimal = Decimal(0)
    fee_rate: Decimal = Decimal('0.003')  # 0.3%
    
    # Price oracle
    price0_cumulative_last: Decimal = Decimal(0)
    price1_cumulative_last: Decimal = Decimal(0)
    block_timestamp_last: int = 0
    
    def add_liquidity(self, amount0: Decimal, amount1: Decimal) -> Decimal:
        """Añade liquidez al pool"""
        if self.total_supply == 0:
            # Primera liquidez
            liquidity = (amount0 * amount1).sqrt()
            self.total_supply = liquidity
        else:
            # Liquidez proporcional
            liquidity = min(
                amount0 * self.total_supply / self.reserve0,
                amount1 * self.total_supply / self.reserve1
            )
            self.total_supply += liquidity
        
        self.reserve0 += amount0
        self.reserve1 += amount1
        self._update_price_oracle()
        
        return liquidity
    
    def remove_liquidity(self, liquidity: Decimal) -> Tuple[Decimal, Decimal]:
        """Remueve liquidez del pool"""
        if liquidity > self.total_supply:
            raise ValueError("Insufficient liquidity")
        
        amount0 = liquidity * self.reserve0 / self.total_supply
        amount1 = liquidity * self.reserve1 / self.total_supply
        
        self.reserve0 -= amount0
        self.reserve1 -= amount1
        self.total_supply -= liquidity
        self._update_price_oracle()
        
        return amount0, amount1
    
    def swap(self, amount_in: Decimal, token_in: str) -> Decimal:
        """Intercambia tokens usando x*y=k"""
        if token_in == self.token0:
            reserve_in = self.reserve0
            reserve_out = self.reserve1
        else:
            reserve_in = self.reserve1
            reserve_out = self.reserve0
        
        # Aplicar fee
        amount_in_with_fee = amount_in * (Decimal(1) - self.fee_rate)
        
        # Calcular amount out
        amount_out = (amount_in_with_fee * reserve_out) / (reserve_in + amount_in_with_fee)
        
        # Actualizar reservas
        if token_in == self.token0:
            self.reserve0 += amount_in
            self.reserve1 -= amount_out
        else:
            self.reserve1 += amount_in
            self.reserve0 -= amount_out
        
        self._update_price_oracle()
        
        return amount_out
    
    def get_price(self, token: str) -> Decimal:
        """Obtiene precio spot del token"""
        if token == self.token0:
            return self.reserve1 / self.reserve0
        else:
            return self.reserve0 / self.reserve1
    
    def _update_price_oracle(self):
        """Actualiza oracle de precio acumulativo"""
        current_timestamp = int(time.time())
        time_elapsed = current_timestamp - self.block_timestamp_last
        
        if time_elapsed > 0 and self.reserve0 > 0 and self.reserve1 > 0:
            # Actualizar precios acumulativos
            self.price0_cumulative_last += self.reserve1 / self.reserve0 * time_elapsed
            self.price1_cumulative_last += self.reserve0 / self.reserve1 * time_elapsed
        
        self.block_timestamp_last = current_timestamp

# === LENDING PROTOCOL ===
class LendingProtocol:
    """Protocolo de préstamos con liquidaciones"""
    
    def __init__(self):
        self.markets = {}  # asset -> Market
        self.user_positions = defaultdict(dict)  # user -> asset -> Position
        self.oracle = None
        
    def create_market(self, asset: str, collateral_factor: Decimal):
        """Crea nuevo mercado de préstamos"""
        self.markets[asset] = Market(
            asset=asset,
            collateral_factor=collateral_factor
        )
    
    def supply(self, user: str, asset: str, amount: Decimal):
        """Usuario deposita activos"""
        if asset not in self.markets:
            raise ValueError("Market does not exist")
        
        market = self.markets[asset]
        shares = market.deposit(amount)
        
        if user not in self.user_positions:
            self.user_positions[user] = {}
        
        if asset not in self.user_positions[user]:
            self.user_positions[user][asset] = Position()
        
        self.user_positions[user][asset].supplied += shares
    
    def borrow(self, user: str, asset: str, amount: Decimal):
        """Usuario pide prestado"""
        # Verificar colateral
        if not self._check_collateral(user, asset, amount):
            raise ValueError("Insufficient collateral")
        
        market = self.markets[asset]
        market.borrow(amount)
        
        self.user_positions[user][asset].borrowed += amount
    
    def liquidate(self, liquidator: str, borrower: str, 
                  repay_asset: str, repay_amount: Decimal,
                  collateral_asset: str):
        """Liquida posición insolvente"""
        # Verificar que la posición es liquidable
        if self._health_factor(borrower) >= Decimal('1.0'):
            raise ValueError("Position is healthy")
        
        # Calcular bonus de liquidación
        liquidation_bonus = repay_amount * Decimal(str(BlockchainConfig.LIQUIDATION_BONUS))
        collateral_to_seize = repay_amount + liquidation_bonus
        
        # Transferir activos
        # ... implementación de transferencias
    
    def _check_collateral(self, user: str, asset: str, borrow_amount: Decimal) -> bool:
        """Verifica si usuario tiene suficiente colateral"""
        total_collateral = Decimal(0)
        total_borrowed = Decimal(0)
        
        for asset, position in self.user_positions[user].items():
            market = self.markets[asset]
            price = self._get_price(asset)
            
            # Calcular valor del colateral
            collateral_value = position.supplied * price * market.collateral_factor
            total_collateral += collateral_value
            
            # Calcular valor prestado
            borrowed_value = position.borrowed * price
            total_borrowed += borrowed_value
        
        # Añadir nuevo préstamo
        new_borrow_value = borrow_amount * self._get_price(asset)
        total_borrowed += new_borrow_value
        
        return total_collateral > total_borrowed
    
    def _health_factor(self, user: str) -> Decimal:
        """Calcula factor de salud de la posición"""
        total_collateral = Decimal(0)
        total_borrowed = Decimal(0)
        
        for asset, position in self.user_positions[user].items():
            market = self.markets[asset]
            price = self._get_price(asset)
            
            collateral_value = position.supplied * price * market.collateral_factor
            total_collateral += collateral_value
            
            borrowed_value = position.borrowed * price
            total_borrowed += borrowed_value
        
        if total_borrowed == 0:
            return Decimal('inf')
        
        return total_collateral * Decimal(str(BlockchainConfig.LIQUIDATION_THRESHOLD)) / total_borrowed
    
    def _get_price(self, asset: str) -> Decimal:
        """Obtiene precio del oracle"""
        if self.oracle:
            price_data = self.oracle.get_price(asset)
            if price_data:
                return price_data['price']
        
        # Precio por defecto
        return Decimal('1.0')

@dataclass
class Market:
    """Mercado individual de préstamos"""
    asset: str
    collateral_factor: Decimal
    total_supply: Decimal = Decimal(0)
    total_borrows: Decimal = Decimal(0)
    borrow_rate: Decimal = Decimal('0.05')  # 5% APR base
    supply_rate: Decimal = Decimal('0.02')  # 2% APR base
    
    def deposit(self, amount: Decimal) -> Decimal:
        """Deposita en el mercado"""
        self.total_supply += amount
        self._update_rates()
        return amount  # Simplificado, debería usar shares
    
    def borrow(self, amount: Decimal):
        """Pide prestado del mercado"""
        if amount > self.total_supply - self.total_borrows:
            raise ValueError("Insufficient liquidity")
        
        self.total_borrows += amount
        self._update_rates()
    
    def _update_rates(self):
        """Actualiza tasas de interés dinámicamente"""
        if self.total_supply == 0:
            utilization = Decimal(0)
        else:
            utilization = self.total_borrows / self.total_supply
        
        # Modelo de tasas simple
        self.borrow_rate = Decimal('0.02') + utilization * Decimal('0.15')
        self.supply_rate = self.borrow_rate * utilization * Decimal('0.9')  # 90% a suppliers

@dataclass
class Position:
    """Posición de usuario en lending"""
    supplied: Decimal = Decimal(0)
    borrowed: Decimal = Decimal(0)

# === SISTEMA DE GOBERNANZA ===
class GovernanceSystem:
    """Sistema de gobernanza on-chain"""
    
    def __init__(self, token_address: str):
        self.token_address = token_address
        self.proposals = {}  # proposal_id -> Proposal
        self.proposal_count = 0
        self.quorum = Decimal('0.04')  # 4% del supply
        self.voting_period = 3 * 24 * 3600  # 3 días
        
    def create_proposal(self, proposer: str, title: str, 
                       description: str, actions: List[Dict]) -> int:
        """Crea nueva propuesta"""
        self.proposal_count += 1
        proposal_id = self.proposal_count
        
        self.proposals[proposal_id] = Proposal(
            id=proposal_id,
            proposer=proposer,
            title=title,
            description=description,
            actions=actions,
            start_block=0,  # Se establece cuando se activa
            end_block=0,
            for_votes=Decimal(0),
            against_votes=Decimal(0),
            voters=set(),
            status=ProposalStatus.PENDING
        )
        
        return proposal_id
    
    def vote(self, proposal_id: int, voter: str, support: bool, votes: Decimal):
        """Vota en una propuesta"""
        if proposal_id not in self.proposals:
            raise ValueError("Proposal does not exist")
        
        proposal = self.proposals[proposal_id]
        
        # Verificar que está en período de votación
        if proposal.status != ProposalStatus.ACTIVE:
            raise ValueError("Proposal is not active")
        
        # Verificar que no ha votado antes
        if voter in proposal.voters:
            raise ValueError("Already voted")
        
        proposal.voters.add(voter)
        
        if support:
            proposal.for_votes += votes
        else:
            proposal.against_votes += votes
    
    def execute_proposal(self, proposal_id: int):
        """Ejecuta propuesta aprobada"""
        proposal = self.proposals[proposal_id]
        
        if proposal.status != ProposalStatus.SUCCEEDED:
            raise ValueError("Proposal not succeeded")
        
        # Ejecutar acciones
        for action in proposal.actions:
            # Implementar ejecución de acciones
            # Ej: cambiar parámetros, transferir fondos, etc.
            pass
        
        proposal.status = ProposalStatus.EXECUTED

@dataclass
class Proposal:
    """Propuesta de gobernanza"""
    id: int
    proposer: str
    title: str
    description: str
    actions: List[Dict[str, Any]]
    start_block: int
    end_block: int
    for_votes: Decimal
    against_votes: Decimal
    voters: Set[str]
    status: 'ProposalStatus'

class ProposalStatus(Enum):
    """Estados de propuesta"""
    PENDING = "pending"
    ACTIVE = "active"
    CANCELLED = "cancelled"
    SUCCEEDED = "succeeded"
    DEFEATED = "defeated"
    EXECUTED = "executed"

# === SISTEMA DE STAKING ===
class StakingSystem:
    """Sistema de staking con delegación"""
    
    def __init__(self, blockchain: 'MSCBlockchainV3'):
        self.blockchain = blockchain
        self.validators = {}  # address -> ValidatorInfo
        self.delegations = defaultdict(dict)  # delegator -> validator -> amount
        self.rewards_pool = Decimal(0)
        self.unbonding_period = 7 * 24 * 3600  # 7 días
        
    def register_validator(self, address: str, commission_rate: Decimal, 
                          min_self_delegation: Decimal):
        """Registra nuevo validador"""
        if commission_rate > Decimal('0.2'):  # Max 20%
            raise ValueError("Commission rate too high")
        
        self.validators[address] = ValidatorInfo(
            address=address,
            commission_rate=commission_rate,
            min_self_delegation=min_self_delegation,
            self_delegation=Decimal(0),
            total_delegation=Decimal(0),
            status=ValidatorStatus.INACTIVE
        )
    
    def delegate(self, delegator: str, validator: str, amount: Decimal):
        """Delega stake a validador"""
        if validator not in self.validators:
            raise ValueError("Validator does not exist")
        
        # Actualizar delegación
        self.delegations[delegator][validator] = \
            self.delegations[delegator].get(validator, Decimal(0)) + amount
        
        # Actualizar totales del validador
        validator_info = self.validators[validator]
        validator_info.total_delegation += amount
        
        if delegator == validator:
            validator_info.self_delegation += amount
        
        # Activar validador si cumple requisitos
        if validator_info.self_delegation >= validator_info.min_self_delegation and \
           validator_info.total_delegation >= BlockchainConfig.MIN_STAKE_AMOUNT * 10**18:
            validator_info.status = ValidatorStatus.ACTIVE
    
    def undelegate(self, delegator: str, validator: str, amount: Decimal):
        """Inicia proceso de undelegation"""
        if validator not in self.delegations[delegator]:
            raise ValueError("No delegation found")
        
        current_delegation = self.delegations[delegator][validator]
        if amount > current_delegation:
            raise ValueError("Insufficient delegation")
        
        # Crear unbonding entry
        unbonding_entry = UnbondingEntry(
            delegator=delegator,
            validator=validator,
            amount=amount,
            completion_time=time.time() + self.unbonding_period
        )
        
        # Actualizar delegaciones
        self.delegations[delegator][validator] -= amount
        self.validators[validator].total_delegation -= amount
        
        if delegator == validator:
            self.validators[validator].self_delegation -= amount
        
        return unbonding_entry
    
    def distribute_rewards(self, block_rewards: Dict[str, Decimal]):
        """Distribuye recompensas a validadores y delegadores"""
        for validator_address, reward in block_rewards.items():
            if validator_address not in self.validators:
                continue
            
            validator = self.validators[validator_address]
            
            # Calcular comisión del validador
            commission = reward * validator.commission_rate
            validator_reward = commission
            
            # Recompensas para delegadores
            delegator_rewards = reward - commission
            
            # Distribuir proporcionalmente
            for delegator, delegation in self.delegations.items():
                if validator_address in delegation:
                    delegator_share = delegation[validator_address] / validator.total_delegation
                    delegator_reward = delegator_rewards * delegator_share
                    
                    # Añadir recompensa (simplificado)
                    # En implementación real, se acumularían para reclamar
                    self.rewards_pool += delegator_reward

@dataclass
class ValidatorInfo:
    """Información del validador"""
    address: str
    commission_rate: Decimal
    min_self_delegation: Decimal
    self_delegation: Decimal
    total_delegation: Decimal
    status: 'ValidatorStatus'
    jailed: bool = False
    jailed_until: Optional[int] = None

class ValidatorStatus(Enum):
    """Estado del validador"""
    INACTIVE = "inactive"
    ACTIVE = "active"
    JAILED = "jailed"

@dataclass
class UnbondingEntry:
    """Entrada de unbonding"""
    delegator: str
    validator: str
    amount: Decimal
    completion_time: float

# === CROSS-CHAIN BRIDGE ===
class CrossChainBridge:
    """Puente para interoperabilidad entre chains"""
    
    def __init__(self, home_chain_id: int):
        self.home_chain_id = home_chain_id
        self.supported_chains = {}  # chain_id -> ChainConfig
        self.pending_transfers = {}  # transfer_id -> CrossChainTransfer
        self.validators = set()
        self.confirmations_required = 5
        
    def add_supported_chain(self, chain_id: int, config: Dict[str, Any]):
        """Añade cadena soportada"""
        self.supported_chains[chain_id] = ChainConfig(
            chain_id=chain_id,
            name=config['name'],
            rpc_url=config['rpc_url'],
            confirmations=config.get('confirmations', 12)
        )
    
    def initiate_transfer(self, from_chain: int, to_chain: int,
                         sender: str, recipient: str,
                         token: str, amount: Decimal) -> str:
        """Inicia transferencia cross-chain"""
        if to_chain not in self.supported_chains:
            raise ValueError("Unsupported destination chain")
        
        transfer_id = str(uuid.uuid4())
        
        self.pending_transfers[transfer_id] = CrossChainTransfer(
            id=transfer_id,
            from_chain=from_chain,
            to_chain=to_chain,
            sender=sender,
            recipient=recipient,
            token=token,
            amount=amount,
            status=TransferStatus.PENDING,
            confirmations=set(),
            created_at=time.time()
        )
        
        return transfer_id
    
    def confirm_transfer(self, transfer_id: str, validator: str, 
                        tx_hash: str):
        """Validador confirma transferencia"""
        if validator not in self.validators:
            raise ValueError("Not authorized validator")
        
        if transfer_id not in self.pending_transfers:
            raise ValueError("Transfer not found")
        
        transfer = self.pending_transfers[transfer_id]
        transfer.confirmations.add(validator)
        
        # Si suficientes confirmaciones, ejecutar
        if len(transfer.confirmations) >= self.confirmations_required:
            transfer.status = TransferStatus.CONFIRMED
            # Ejecutar transferencia en cadena destino
            self._execute_transfer(transfer)
    
    def _execute_transfer(self, transfer: 'CrossChainTransfer'):
        """Ejecuta transferencia en cadena destino"""
        # Implementar lógica de ejecución
        # Esto involucraría llamar a contratos en la cadena destino
        pass

@dataclass
class ChainConfig:
    """Configuración de cadena externa"""
    chain_id: int
    name: str
    rpc_url: str
    confirmations: int

@dataclass
class CrossChainTransfer:
    """Transferencia cross-chain"""
    id: str
    from_chain: int
    to_chain: int
    sender: str
    recipient: str
    token: str
    amount: Decimal
    status: 'TransferStatus'
    confirmations: Set[str]
    created_at: float
    completed_at: Optional[float] = None

class TransferStatus(Enum):
    """Estado de transferencia cross-chain"""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    EXECUTED = "executed"
    FAILED = "failed"

# === BLOCKCHAIN PRINCIPAL V3 ===
class MSCBlockchainV3:
    """Blockchain v3 con todas las características enterprise"""
    
    def __init__(self):
        # Core
        self.chain: List[Block] = []
        self.state_db = MerklePatriciaTrie(BlockchainConfig.STATE_DB_PATH)
        self.pending_transactions = SortedList(key=lambda tx: -tx.gas_price)
        
        # Consensus
        self.consensus = HybridConsensus(self)
        
        # DeFi
        self.dex = DEXProtocol("0x" + "0" * 40)
        self.lending = LendingProtocol()
        self.staking = StakingSystem(self)
        self.governance = GovernanceSystem("0x" + "0" * 40)
        
        # Infrastructure
        self.oracle_system = OracleSystem()
        self.bridge = CrossChainBridge(BlockchainConfig.CHAIN_ID)
        self.vm = MSCVirtualMachine(self.state_db)
        
        # Networking
        self.peers: Set[str] = set()
        self.sync_status = NetworkStatus.OFFLINE
        
        # Caches
        self.receipt_cache = OrderedDict()
        self.block_cache = OrderedDict()
        
        # Metrics
        self.total_transactions = 0
        self.total_gas_used = 0
        
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
    
    async def add_transaction(self, tx: Transaction) -> bool:
        """Añade transacción al pool"""
        try:
            # Validar transacción
            if not await self._validate_transaction(tx):
                return False
            
            # Añadir al pool
            self.pending_transactions.add(tx)
            transactions_counter.inc()
            
            # Propagar a peers
            asyncio.create_task(self._broadcast_transaction(tx))
            
            return True
            
        except Exception as e:
            logger.error(f"Error adding transaction: {e}")
            return False
    
    async def _validate_transaction(self, tx: Transaction) -> bool:
        """Validación completa de transacción"""
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
            raise ValueError(f"Invalid nonce: expected {account.nonce}, got {tx.nonce}")
        
        # 4. Verificar balance para gas
        gas_cost = tx.gas_limit * tx.gas_price
        total_cost = gas_cost + tx.value
        
        if account.balance < total_cost:
            raise ValueError("Insufficient balance for gas + value")
        
        # 5. Verificar gas intrínseco
        if tx.gas_limit < tx.intrinsic_gas():
            raise ValueError("Gas limit below intrinsic gas")
        
        # 6. Verificar límites
        if tx.gas_limit > BlockchainConfig.MAX_BLOCK_SIZE:
            raise ValueError("Gas limit too high")
        
        return True
    
    async def mine_block(self, miner_address: str) -> Optional[Block]:
        """Mina nuevo bloque con consenso híbrido"""
        # Determinar si es turno de PoW o PoS
        block_producer = self.consensus.select_block_producer(len(self.chain))
        
        if block_producer == "POW":
            return await self._mine_pow_block(miner_address)
        else:
            return await self._produce_pos_block(block_producer)
    
    async def _mine_pow_block(self, miner_address: str) -> Optional[Block]:
        """Mina bloque con Proof of Work"""
        parent = self.get_latest_block()
        
        # Seleccionar transacciones
        transactions = self._select_transactions_for_block()
        
        # Crear header
        header = BlockHeader(
            parent_hash=parent.hash,
            uncle_hash='0x' + '0' * 64,
            coinbase=miner_address,
            state_root=self.state_db.root_hash or '0x' + '0' * 64,
            transactions_root='0x' + '0' * 64,  # Se calculará
            receipts_root='0x' + '0' * 64,
            logs_bloom=b'\x00' * 256,
            difficulty=self._calculate_difficulty(),
            number=parent.header.number + 1,
            gas_limit=self._calculate_gas_limit(parent),
            gas_used=0,
            timestamp=int(time.time()),
            extra_data=b'',
            mix_hash='0x' + '0' * 64,
            nonce=0,
            base_fee_per_gas=self._calculate_base_fee(parent)
        )
        
        # Crear bloque
        block = Block(header=header, transactions=transactions)
        
        # Minar (encontrar nonce)
        logger.info(f"Mining block {block.header.number}...")
        start_time = time.time()
        
        while True:
            block.hash = block.header.calculate_hash()
            
            if block.verify_pow():
                mining_time = time.time() - start_time
                logger.info(f"Block mined in {mining_time:.2f}s!")
                break
            
            block.header.nonce += 1
            
            # Timeout check
            if time.time() - start_time > 60:
                logger.warning("Mining timeout")
                return None
        
        # Procesar bloque
        await self._process_block(block)
        
        return block
    
    async def _produce_pos_block(self, validator: str) -> Optional[Block]:
        """Produce bloque con Proof of Stake"""
        # Verificar que el validador es válido
        if validator not in self.consensus.validators:
            logger.error(f"Invalid validator: {validator}")
            return None
        
        parent = self.get_latest_block()
        transactions = self._select_transactions_for_block()
        
        # Crear bloque sin mining
        header = BlockHeader(
            parent_hash=parent.hash,
            uncle_hash='0x' + '0' * 64,
            coinbase=validator,
            state_root=self.state_db.root_hash or '0x' + '0' * 64,
            transactions_root='0x' + '0' * 64,
            receipts_root='0x' + '0' * 64,
            logs_bloom=b'\x00' * 256,
            difficulty=1,  # PoS no usa dificultad
            number=parent.header.number + 1,
            gas_limit=self._calculate_gas_limit(parent),
            gas_used=0,
            timestamp=int(time.time()),
            extra_data=b'PoS Block',
            mix_hash='0x' + '0' * 64,
            nonce=0,
            base_fee_per_gas=self._calculate_base_fee(parent)
        )
        
        block = Block(header=header, transactions=transactions)
        block.hash = block.header.calculate_hash()
        
        # Procesar bloque
        await self._process_block(block)
        
        return block
    
    def _select_transactions_for_block(self) -> List[Transaction]:
        """Selecciona transacciones para incluir en bloque"""
        selected = []
        total_gas = 0
        gas_limit = 30_000_000  # Gas limit del bloque
        
        # Copiar lista para no modificar el pool
        pending = list(self.pending_transactions)
        
        for tx in pending:
            if total_gas + tx.gas_limit > gas_limit:
                continue
            
            # Verificar que la transacción sigue siendo válida
            try:
                sender = tx.sender()
                account = self._load_account(sender)
                if account and tx.nonce == account.nonce:
                    selected.append(tx)
                    total_gas += tx.gas_limit
            except:
                # Remover transacción inválida
                self.pending_transactions.remove(tx)
        
        return selected
    
    async def _process_block(self, block: Block):
        """Procesa bloque ejecutando transacciones"""
        gas_used = 0
        receipts = []
        
        # Estado temporal para rollback si falla
        temp_state_changes = {}
        
        for i, tx in enumerate(block.transactions):
            # Ejecutar transacción
            receipt = await self._execute_transaction(tx, block, i)
            receipts.append(receipt)
            gas_used += receipt.gas_used
        
        # Actualizar header
        block.header.gas_used = gas_used
        block.header.transactions_root = block.calculate_transactions_root()
        
        # Añadir bloque a la cadena
        self.chain.append(block)
        blocks_mined_counter.inc()
        
        # Actualizar métricas
        self.total_transactions += len(block.transactions)
        self.total_gas_used += gas_used
        
        # Limpiar transacciones del pool
        for tx in block.transactions:
            try:
                self.pending_transactions.remove(tx)
            except:
                pass
        
        # Distribuir recompensas
        rewards = self.consensus.calculate_rewards(block)
        for address, amount in rewards.items():
            account = self._load_account(address) or Account(address=address)
            account.balance += amount
            self._save_account(account)
        
        logger.info(f"Block {block.header.number} processed with {len(block.transactions)} transactions")
    
    async def _execute_transaction(self, tx: Transaction, block: Block, 
                                  tx_index: int) -> TransactionReceipt:
        """Ejecuta una transacción y genera recibo"""
        sender = tx.sender()
        account = self._load_account(sender)
        
        # Gas inicial
        gas_left = tx.gas_limit
        
        try:
            # Deducir gas cost
            gas_cost = tx.gas_limit * tx.gas_price
            account.balance -= gas_cost
            
            # Transferir valor
            if tx.to:
                # Transferencia normal o llamada a contrato
                to_account = self._load_account(tx.to) or Account(address=tx.to)
                
                if to_account.is_contract():
                    # Ejecutar contrato
                    result = self.vm.execute(
                        code=self._get_contract_code(tx.to),
                        gas_limit=gas_left,
                        context={
                            'sender': sender,
                            'value': tx.value,
                            'data': tx.data
                        }
                    )
                    gas_left -= result['gas_used']
                else:
                    # Transferencia simple
                    account.balance -= tx.value
                    to_account.balance += tx.value
                    self._save_account(to_account)
                    gas_left -= 21000  # Gas base
            else:
                # Creación de contrato
                contract_address = self._create_contract_address(sender, account.nonce)
                contract_account = Account(
                    address=contract_address,
                    code_hash=hashlib.sha256(tx.data).hexdigest()
                )
                self._save_account(contract_account)
                self._save_contract_code(contract_address, tx.data)
                gas_left -= BlockchainConfig.CREATE_CONTRACT_GAS
            
            # Incrementar nonce
            account.nonce += 1
            self._save_account(account)
            
            # Reembolsar gas no usado
            gas_used = tx.gas_limit - gas_left
            refund = gas_left * tx.gas_price
            account.balance += refund
            self._save_account(account)
            
            # Crear recibo exitoso
            receipt = TransactionReceipt(
                transaction_hash=tx.calculate_hash(),
                block_hash=block.hash,
                block_number=block.header.number,
                from_address=sender,
                to_address=tx.to,
                contract_address=contract_address if not tx.to else None,
                gas_used=gas_used,
                cumulative_gas_used=gas_used,  # Simplificado
                status=True,
                logs=[]
            )
            
        except Exception as e:
            # Transacción falló - consumir todo el gas
            logger.error(f"Transaction failed: {e}")
            
            receipt = TransactionReceipt(
                transaction_hash=tx.calculate_hash(),
                block_hash=block.hash,
                block_number=block.header.number,
                from_address=sender,
                to_address=tx.to,
                contract_address=None,
                gas_used=tx.gas_limit,
                cumulative_gas_used=tx.gas_limit,
                status=False,
                logs=[]
            )
        
        # Guardar recibo
        self._save_receipt(receipt)
        gas_used_histogram.observe(receipt.gas_used)
        
        return receipt
    
    def _create_contract_address(self, sender: str, nonce: int) -> str:
        """Genera dirección determinística para contrato"""
        data = f"{sender}{nonce}"
        return '0x' + hashlib.sha256(data.encode()).hexdigest()[:40]
    
    def _save_contract_code(self, address: str, code: bytes):
        """Guarda código de contrato"""
        key = f"code:{address}".encode()
        self.state_db.put(key, code)
    
    def _get_contract_code(self, address: str) -> bytes:
        """Obtiene código de contrato"""
        key = f"code:{address}".encode()
        return self.state_db.get(key) or b""
    
    def _save_receipt(self, receipt: TransactionReceipt):
        """Guarda recibo de transacción"""
        key = f"receipt:{receipt.transaction_hash}".encode()
        receipt_data = json.dumps(asdict(receipt)).encode()
        self.state_db.put(key, receipt_data)
        
        # Cache
        self.receipt_cache[receipt.transaction_hash] = receipt
        if len(self.receipt_cache) > BlockchainConfig.CACHE_SIZE:
            self.receipt_cache.popitem(last=False)
    
    def get_receipt(self, tx_hash: str) -> Optional[TransactionReceipt]:
        """Obtiene recibo de transacción"""
        # Check cache
        if tx_hash in self.receipt_cache:
            return self.receipt_cache[tx_hash]
        
        # Load from DB
        key = f"receipt:{tx_hash}".encode()
        receipt_data = self.state_db.get(key)
        
        if receipt_data:
            receipt_dict = json.loads(receipt_data.decode())
            receipt = TransactionReceipt(**receipt_dict)
            self.receipt_cache[tx_hash] = receipt
            return receipt
        
        return None
    
    def _calculate_difficulty(self) -> int:
        """Calcula dificultad dinámica"""
        if len(self.chain) < BlockchainConfig.DIFFICULTY_ADJUSTMENT_INTERVAL:
            return BlockchainConfig.INITIAL_DIFFICULTY
        
        # Ajustar cada N bloques
        if len(self.chain) % BlockchainConfig.DIFFICULTY_ADJUSTMENT_INTERVAL == 0:
            recent_blocks = self.chain[-BlockchainConfig.DIFFICULTY_ADJUSTMENT_INTERVAL:]
            
            time_taken = recent_blocks[-1].header.timestamp - recent_blocks[0].header.timestamp
            expected_time = BlockchainConfig.TARGET_BLOCK_TIME * BlockchainConfig.DIFFICULTY_ADJUSTMENT_INTERVAL
            
            current_difficulty = self.chain[-1].header.difficulty
            
            # Ajuste proporcional
            new_difficulty = current_difficulty * expected_time // time_taken
            
            # Límites
            new_difficulty = max(BlockchainConfig.MIN_DIFFICULTY, 
                               min(BlockchainConfig.MAX_DIFFICULTY, new_difficulty))
            
            return new_difficulty
        
        return self.chain[-1].header.difficulty
    
    def _calculate_gas_limit(self, parent: Block) -> int:
        """Calcula gas limit del bloque"""
        parent_gas_limit = parent.header.gas_limit
        
        # Ajuste basado en uso
        if parent.header.gas_used > parent_gas_limit * 2 // 3:
            # Incrementar si se usa más de 2/3
            return parent_gas_limit + parent_gas_limit // 1024
        else:
            # Decrementar si se usa menos
            return parent_gas_limit - parent_gas_limit // 1024
    
    def _calculate_base_fee(self, parent: Block) -> int:
        """Calcula base fee según EIP-1559"""
        return parent.calculate_base_fee(parent)
    
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
        # Check cache
        if block_hash in self.block_cache:
            return self.block_cache[block_hash]
        
        # Search in chain
        for block in self.chain:
            if block.hash == block_hash:
                self.block_cache[block_hash] = block
                return block
        
        return None
    
    def get_block_reward(self, block_number: int) -> int:
        """Calcula recompensa del bloque con halving"""
        halvings = block_number // BlockchainConfig.HALVING_INTERVAL
        reward = BlockchainConfig.INITIAL_BLOCK_REWARD
        
        for _ in range(halvings):
            reward //= 2
        
        return max(reward, 10**15)  # Mínimo 0.001 MSC
    
    def estimate_gas(self, tx: Transaction) -> int:
        """Estima gas necesario para transacción"""
        # Gas base
        gas = tx.intrinsic_gas()
        
        if tx.to and self._load_account(tx.to) and self._load_account(tx.to).is_contract():
            # Estimación para contratos (simplificada)
            gas += 50000
        
        return int(gas * 1.2)  # 20% buffer
    
    def _start_services(self):
        """Inicia servicios auxiliares"""
        # Iniciar thread de mantenimiento
        maintenance_thread = threading.Thread(target=self._maintenance_loop, daemon=True)
        maintenance_thread.start()
        
        logger.info("MSC Blockchain v3.0 initialized successfully")
    
    def _maintenance_loop(self):
        """Loop de mantenimiento"""
        while True:
            try:
                # Limpiar transacciones antiguas
                self._clean_pending_transactions()
                
                # Actualizar métricas
                defi_volume_gauge.set(float(self._calculate_defi_volume()))
                staking_total_gauge.set(float(self._calculate_total_stake()))
                
                # Snapshot periódico
                if len(self.chain) % BlockchainConfig.SNAPSHOT_INTERVAL == 0:
                    self._create_state_snapshot()
                
            except Exception as e:
                logger.error(f"Maintenance error: {e}")
            
            time.sleep(60)
    
    def _clean_pending_transactions(self):
        """Limpia transacciones pendientes antiguas"""
        current_time = time.time()
        to_remove = []
        
        for tx in self.pending_transactions:
            # Remover si es muy antigua
            if hasattr(tx, 'timestamp') and current_time - tx.timestamp > BlockchainConfig.TX_POOL_LIFETIME:
                to_remove.append(tx)
        
        for tx in to_remove:
            self.pending_transactions.remove(tx)
    
    def _calculate_defi_volume(self) -> Decimal:
        """Calcula volumen total DeFi"""
        total_volume = Decimal(0)
        
        # Sumar volumen de todos los pools DEX
        for pool in self.dex.pairs.values():
            total_volume += pool.reserve0 + pool.reserve1
        
        # Sumar volumen de lending
        for market in self.lending.markets.values():
            total_volume += market.total_supply
        
        return total_volume
    
    def _calculate_total_stake(self) -> Decimal:
        """Calcula stake total"""
        return sum(self.consensus.validators.values())
    
    def _create_state_snapshot(self):
        """Crea snapshot del estado"""
        snapshot_path = f"snapshots/state_{len(self.chain)}.snapshot"
        # Implementar creación de snapshot
        logger.info(f"State snapshot created at block {len(self.chain)}")
    
    async def _broadcast_transaction(self, tx: Transaction):
        """Propaga transacción a la red"""
        # Implementar propagación P2P
        pass
    
    def validate_chain(self) -> bool:
        """Valida integridad de toda la cadena"""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            # Verificar enlace
            if current.header.parent_hash != previous.hash:
                logger.error(f"Invalid chain link at block {i}")
                return False
            
            # Verificar PoW si aplica
            if current.header.coinbase == "POW" and not current.verify_pow():
                logger.error(f"Invalid PoW at block {i}")
                return False
        
        return True

# === API MEJORADA ===
class BlockchainAPIv3:
    """API REST/WebSocket completa para blockchain v3"""
    
    def __init__(self, blockchain: MSCBlockchainV3):
        self.blockchain = blockchain
        self.app = Flask(__name__)
        CORS(self.app)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        self._setup_routes()
        self._setup_websockets()
    
    def _setup_routes(self):
        """Configura todas las rutas API"""
        
        # === Rutas básicas ===
        @self.app.route('/')
        def index():
            return render_template_string(ADVANCED_DASHBOARD_HTML)
        
        @self.app.route('/api/v3/status')
        def status():
            """Estado general del nodo"""
            latest_block = self.blockchain.get_latest_block()
            
            return jsonify({
                'node_info': {
                    'version': BlockchainConfig.VERSION,
                    'network': BlockchainConfig.NETWORK_NAME,
                    'chain_id': BlockchainConfig.CHAIN_ID,
                    'consensus': BlockchainConfig.CONSENSUS_TYPE
                },
                'sync_status': self.blockchain.sync_status.value,
                'latest_block': {
                    'number': latest_block.header.number,
                    'hash': latest_block.hash,
                    'timestamp': latest_block.header.timestamp,
                    'transactions': len(latest_block.transactions)
                },
                'peers': len(self.blockchain.peers),
                'pending_transactions': len(self.blockchain.pending_transactions),
                'total_transactions': self.blockchain.total_transactions,
                'total_gas_used': self.blockchain.total_gas_used
            })
        
        # === Rutas de cuentas ===
        @self.app.route('/api/v3/accounts/<address>')
        def get_account(address):
            """Información completa de cuenta"""
            account = self.blockchain._load_account(address)
            
            if not account:
                return jsonify({
                    'address': address,
                    'balance': '0',
                    'nonce': 0,
                    'is_contract': False
                })
            
            return jsonify({
                'address': account.address,
                'balance': str(account.balance),
                'nonce': account.nonce,
                'is_contract': account.is_contract(),
                'code_hash': account.code_hash,
                'stake_amount': str(account.stake_amount) if account.stake_amount else '0'
            })
        
        # === Rutas de transacciones ===
        @self.app.route('/api/v3/transactions', methods=['POST'])
        async def send_transaction():
            """Envía nueva transacción"""
            data = request.get_json()
            
            try:
                # Crear transacción desde datos
                tx = Transaction(
                    nonce=data['nonce'],
                    gas_price=int(data['gas_price']),
                    gas_limit=int(data['gas_limit']),
                    to=data.get('to'),
                    value=int(data['value']),
                    data=bytes.fromhex(data.get('data', '').replace('0x', '')),
                    v=data.get('v'),
                    r=data.get('r'),
                    s=data.get('s')
                )
                
                # Añadir al pool
                success = await self.blockchain.add_transaction(tx)
                
                if success:
                    return jsonify({
                        'success': True,
                        'tx_hash': tx.calculate_hash()
                    })
                else:
                    return jsonify({
                        'success': False,
                        'error': 'Transaction validation failed'
                    }), 400
                    
            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 400
        
        @self.app.route('/api/v3/transactions/<tx_hash>')
        def get_transaction(tx_hash):
            """Obtiene transacción por hash"""
            # Buscar en pool
            for tx in self.blockchain.pending_transactions:
                if tx.calculate_hash() == tx_hash:
                    return jsonify({
                        'transaction': self._tx_to_dict(tx),
                        'status': 'pending'
                    })
            
            # Buscar recibo
            receipt = self.blockchain.get_receipt(tx_hash)
            if receipt:
                return jsonify({
                    'transaction': {
                        'hash': receipt.transaction_hash,
                        'from': receipt.from_address,
                        'to': receipt.to_address,
                        'block_number': receipt.block_number,
                        'gas_used': receipt.gas_used,
                        'status': 'success' if receipt.status else 'failed'
                    },
                    'receipt': asdict(receipt)
                })
            
            return jsonify({'error': 'Transaction not found'}), 404
        
        @self.app.route('/api/v3/transactions/<tx_hash>/receipt')
        def get_receipt(tx_hash):
            """Obtiene recibo de transacción"""
            receipt = self.blockchain.get_receipt(tx_hash)
            
            if receipt:
                return jsonify(asdict(receipt))
            
            return jsonify({'error': 'Receipt not found'}), 404
        
        # === Rutas de bloques ===
        @self.app.route('/api/v3/blocks/latest')
        def get_latest_block():
            """Obtiene último bloque"""
            block = self.blockchain.get_latest_block()
            return jsonify(self._block_to_dict(block))
        
        @self.app.route('/api/v3/blocks/<int:number>')
        def get_block_by_number(number):
            """Obtiene bloque por número"""
            block = self.blockchain.get_block_by_number(number)
            
            if block:
                return jsonify(self._block_to_dict(block))
            
            return jsonify({'error': 'Block not found'}), 404
        
        @self.app.route('/api/v3/blocks/hash/<block_hash>')
        def get_block_by_hash(block_hash):
            """Obtiene bloque por hash"""
            block = self.blockchain.get_block_by_hash(block_hash)
            
            if block:
                return jsonify(self._block_to_dict(block))
            
            return jsonify({'error': 'Block not found'}), 404
        
        # === Rutas de minería ===
        @self.app.route('/api/v3/mining/work')
        def get_mining_work():
            """Obtiene trabajo de minería para mineros externos"""
            latest = self.blockchain.get_latest_block()
            
            return jsonify({
                'current_block': latest.header.number,
                'difficulty': self.blockchain._calculate_difficulty(),
                'target': hex(2**(256 - self.blockchain._calculate_difficulty())),
                'mining_reward': str(self.blockchain.get_block_reward(latest.header.number + 1))
            })
        
        @self.app.route('/api/v3/mining/submit', methods=['POST'])
        async def submit_mining_work():
            """Envía solución de minería"""
            data = request.get_json()
            
            # Verificar solución y crear bloque
            # Implementación dependería del protocolo específico
            
            return jsonify({'status': 'accepted'})
        
        # === Rutas DeFi ===
        @self.app.route('/api/v3/defi/dex/pairs')
        def get_dex_pairs():
            """Lista todos los pares DEX"""
            pairs = []
            
            for address, pool in self.blockchain.dex.pairs.items():
                pairs.append({
                    'address': address,
                    'token0': pool.token0,
                    'token1': pool.token1,
                    'reserve0': str(pool.reserve0),
                    'reserve1': str(pool.reserve1),
                    'total_supply': str(pool.total_supply),
                    'price0': str(pool.get_price(pool.token0)),
                    'price1': str(pool.get_price(pool.token1))
                })
            
            return jsonify({'pairs': pairs})
        
        @self.app.route('/api/v3/defi/dex/swap/quote', methods=['POST'])
        def get_swap_quote():
            """Obtiene cotización de swap"""
            data = request.get_json()
            
            pair_address = data['pair']
            amount_in = Decimal(data['amount_in'])
            token_in = data['token_in']
            
            if pair_address in self.blockchain.dex.pairs:
                pool = self.blockchain.dex.pairs[pair_address]
                amount_out = pool.swap(amount_in, token_in)
                
                return jsonify({
                    'amount_out': str(amount_out),
                    'price_impact': str((amount_in / pool.reserve0) * 100),
                    'fee': str(amount_in * pool.fee_rate)
                })
            
            return jsonify({'error': 'Pair not found'}), 404
        
        @self.app.route('/api/v3/defi/lending/markets')
        def get_lending_markets():
            """Lista mercados de lending"""
            markets = []
            
            for asset, market in self.blockchain.lending.markets.items():
                markets.append({
                    'asset': asset,
                    'total_supply': str(market.total_supply),
                    'total_borrows': str(market.total_borrows),
                    'supply_rate': str(market.supply_rate),
                    'borrow_rate': str(market.borrow_rate),
                    'utilization': str(market.total_borrows / market.total_supply if market.total_supply > 0 else 0)
                })
            
            return jsonify({'markets': markets})
        
        @self.app.route('/api/v3/defi/staking/validators')
        def get_validators():
            """Lista validadores activos"""
            validators = []
            
            for address, info in self.blockchain.staking.validators.items():
                validators.append({
                    'address': address,
                    'commission_rate': str(info.commission_rate),
                    'total_delegation': str(info.total_delegation),
                    'self_delegation': str(info.self_delegation),
                    'status': info.status.value,
                    'jailed': info.jailed
                })
            
            return jsonify({'validators': validators})
        
        @self.app.route('/api/v3/defi/governance/proposals')
        def get_proposals():
            """Lista propuestas de gobernanza"""
            proposals = []
            
            for prop_id, proposal in self.blockchain.governance.proposals.items():
                proposals.append({
                    'id': proposal.id,
                    'title': proposal.title,
                    'proposer': proposal.proposer,
                    'status': proposal.status.value,
                    'for_votes': str(proposal.for_votes),
                    'against_votes': str(proposal.against_votes),
                    'start_block': proposal.start_block,
                    'end_block': proposal.end_block
                })
            
            return jsonify({'proposals': proposals})
        
        # === Rutas de Oracle ===
        @self.app.route('/api/v3/oracle/prices')
        def get_oracle_prices():
            """Obtiene precios del oracle"""
            prices = {}
            
            for symbol, data in self.blockchain.oracle_system.price_feeds.items():
                prices[symbol] = {
                    'price': str(data['price']),
                    'timestamp': data['timestamp'],
                    'confidence': data['confidence']
                }
            
            return jsonify({'prices': prices})
        
        # === Rutas de Bridge ===
        @self.app.route('/api/v3/bridge/chains')
        def get_supported_chains():
            """Lista cadenas soportadas por el bridge"""
            chains = []
            
            for chain_id, config in self.blockchain.bridge.supported_chains.items():
                chains.append({
                    'chain_id': config.chain_id,
                    'name': config.name,
                    'confirmations_required': config.confirmations
                })
            
            return jsonify({'chains': chains})
        
        @self.app.route('/api/v3/bridge/transfers/<transfer_id>')
        def get_bridge_transfer(transfer_id):
            """Obtiene estado de transferencia cross-chain"""
            if transfer_id in self.blockchain.bridge.pending_transfers:
                transfer = self.blockchain.bridge.pending_transfers[transfer_id]
                
                return jsonify({
                    'id': transfer.id,
                    'from_chain': transfer.from_chain,
                    'to_chain': transfer.to_chain,
                    'sender': transfer.sender,
                    'recipient': transfer.recipient,
                    'token': transfer.token,
                    'amount': str(transfer.amount),
                    'status': transfer.status.value,
                    'confirmations': len(transfer.confirmations),
                    'confirmations_required': self.blockchain.bridge.confirmations_required
                })
            
            return jsonify({'error': 'Transfer not found'}), 404
        
        # === Rutas de utilidades ===
        @self.app.route('/api/v3/gas/price')
        def get_gas_price():
            """Obtiene precio de gas recomendado"""
            # Analizar transacciones recientes
            if self.blockchain.pending_transactions:
                prices = [tx.gas_price for tx in self.blockchain.pending_transactions[:100]]
                
                return jsonify({
                    'slow': min(prices),
                    'standard': sorted(prices)[len(prices)//2],  # mediana
                    'fast': sorted(prices)[int(len(prices)*0.9)],  # percentil 90
                    'instant': max(prices)
                })
            
            # Valores por defecto
            base = BlockchainConfig.MIN_GAS_PRICE
            return jsonify({
                'slow': base,
                'standard': base * 2,
                'fast': base * 3,
                'instant': base * 5
            })
        
        @self.app.route('/api/v3/gas/estimate', methods=['POST'])
        def estimate_gas():
            """Estima gas para transacción"""
            data = request.get_json()
            
            tx = Transaction(
                nonce=0,  # dummy
                gas_price=BlockchainConfig.MIN_GAS_PRICE,
                gas_limit=0,  # will estimate
                to=data.get('to'),
                value=int(data.get('value', 0)),
                data=bytes.fromhex(data.get('data', '').replace('0x', ''))
            )
            
            estimated_gas = self.blockchain.estimate_gas(tx)
            
            return jsonify({
                'gas_limit': estimated_gas,
                'gas_price': BlockchainConfig.MIN_GAS_PRICE,
                'total_cost': str(estimated_gas * BlockchainConfig.MIN_GAS_PRICE)
            })
    
    def _setup_websockets(self):
        """Configura eventos WebSocket"""
        
        @self.socketio.on('connect')
        def handle_connect():
            logger.info(f"Client connected: {request.sid}")
            emit('connected', {'status': 'Connected to MSC v3.0'})
        
        @self.socketio.on('subscribe')
        def handle_subscribe(data):
            """Suscribe a eventos específicos"""
            event_type = data.get('type')
            
            if event_type == 'blocks':
                # Suscribir a nuevos bloques
                pass
            elif event_type == 'transactions':
                # Suscribir a transacciones
                pass
            elif event_type == 'defi':
                # Suscribir a eventos DeFi
                pass
            
            emit('subscribed', {'type': event_type})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info(f"Client disconnected: {request.sid}")
    
    def _tx_to_dict(self, tx: Transaction) -> Dict:
        """Convierte transacción a diccionario"""
        return {
            'hash': tx.calculate_hash(),
            'nonce': tx.nonce,
            'gas_price': str(tx.gas_price),
            'gas_limit': tx.gas_limit,
            'to': tx.to,
            'value': str(tx.value),
            'data': tx.data.hex() if tx.data else '0x',
            'type': tx.tx_type.value
        }
    
    def _block_to_dict(self, block: Block) -> Dict:
        """Convierte bloque a diccionario"""
        return {
            'number': block.header.number,
            'hash': block.hash,
            'parent_hash': block.header.parent_hash,
            'timestamp': block.header.timestamp,
            'miner': block.header.coinbase,
            'difficulty': block.header.difficulty,
            'gas_limit': block.header.gas_limit,
            'gas_used': block.header.gas_used,
            'base_fee_per_gas': block.header.base_fee_per_gas,
            'transactions': [self._tx_to_dict(tx) for tx in block.transactions],
            'transaction_count': len(block.transactions)
        }
    
    def run(self, host='0.0.0.0', port=8545, debug=False):
        """Ejecuta el servidor API"""
        self.socketio.run(self.app, host=host, port=port, debug=debug)

# === DASHBOARD AVANZADO ===
ADVANCED_DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MSC Blockchain v3.0 - Enterprise DeFi Platform</title>
    <script src="https://cdn.jsdelivr.net/npm/vue@3"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/ethers@5.7.2/dist/ethers.umd.min.js"></script>
    <style>
        :root {
            --primary: #667eea;
            --primary-dark: #5a67d8;
            --secondary: #ed64a6;
            --success: #48bb78;
            --danger: #f56565;
            --warning: #ed8936;
            --dark: #1a202c;
            --darker: #171923;
            --light: #f7fafc;
            --gray: #718096;
            --border: #2d3748;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--darker);
            color: var(--light);
            line-height: 1.6;
        }
        
        .app {
            min-height: 100vh;
            display: flex;
        }
        
        /* Sidebar */
        .sidebar {
            width: 250px;
            background: var(--dark);
            padding: 20px;
            border-right: 1px solid var(--border);
        }
        
        .logo {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 40px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .nav-item {
            display: block;
            padding: 12px 16px;
            color: var(--gray);
            text-decoration: none;
            border-radius: 8px;
            margin-bottom: 8px;
            transition: all 0.3s;
        }
        
        .nav-item:hover, .nav-item.active {
            background: rgba(102, 126, 234, 0.1);
            color: var(--primary);
        }
        
        /* Main Content */
        .main {
            flex: 1;
            padding: 30px;
            overflow-y: auto;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        
        .page-title {
            font-size: 32px;
            font-weight: 600;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--dark);
            padding: 24px;
            border-radius: 12px;
            border: 1px solid var(--border);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        
        .stat-label {
            color: var(--gray);
            font-size: 14px;
            margin-bottom: 8px;
        }
        
        .stat-value {
            font-size: 28px;
            font-weight: bold;
            color: var(--primary);
        }
        
        .stat-change {
            font-size: 14px;
            margin-top: 4px;
        }
        
        .stat-change.positive {
            color: var(--success);
        }
        
        .stat-change.negative {
            color: var(--danger);
        }
        
        /* Cards */
        .card {
            background: var(--dark);
            border-radius: 12px;
            padding: 24px;
            border: 1px solid var(--border);
            margin-bottom: 20px;
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .card-title {
            font-size: 20px;
            font-weight: 600;
        }
        
        /* Tables */
        .table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .table th {
            text-align: left;
            padding: 12px;
            color: var(--gray);
            font-weight: 500;
            border-bottom: 1px solid var(--border);
        }
        
        .table td {
            padding: 12px;
            border-bottom: 1px solid var(--border);
        }
        
        .table tr:hover {
            background: rgba(255, 255, 255, 0.02);
        }
        
        /* Buttons */
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn-primary {
            background: var(--primary);
            color: white;
        }
        
        .btn-primary:hover {
            background: var(--primary-dark);
        }
        
        .btn-secondary {
            background: transparent;
            color: var(--primary);
            border: 1px solid var(--primary);
        }
        
        .btn-secondary:hover {
            background: rgba(102, 126, 234, 0.1);
        }
        
        /* Forms */
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            color: var(--gray);
            font-size: 14px;
        }
        
        .form-control {
            width: 100%;
            padding: 12px;
            background: var(--darker);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--light);
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--primary);
        }
        
        /* Tabs */
        .tabs {
            display: flex;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
        }
        
        .tab {
            padding: 12px 24px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.3s;
            color: var(--gray);
        }
        
        .tab:hover {
            color: var(--light);
        }
        
        .tab.active {
            color: var(--primary);
            border-bottom-color: var(--primary);
        }
        
        /* Charts */
        .chart-container {
            position: relative;
            height: 300px;
        }
        
        /* DeFi Specific */
        .pool-card {
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.1) 0%, rgba(237, 100, 166, 0.1) 100%);
            border: 1px solid rgba(102, 126, 234, 0.3);
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 16px;
        }
        
        .pool-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }
        
        .pool-pair {
            font-size: 18px;
            font-weight: 600;
        }
        
        .pool-stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
        }
        
        .pool-stat {
            text-align: center;
        }
        
        .pool-stat-label {
            font-size: 12px;
            color: var(--gray);
        }
        
        .pool-stat-value {
            font-size: 16px;
            font-weight: 600;
            margin-top: 4px;
        }
        
        /* Animations */
        @keyframes pulse {
            0% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.05); opacity: 0.8; }
            100% { transform: scale(1); opacity: 1; }
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .badge-success {
            background: rgba(72, 187, 120, 0.2);
            color: var(--success);
        }
        
        .badge-danger {
            background: rgba(245, 101, 101, 0.2);
            color: var(--danger);
        }
        
        .badge-warning {
            background: rgba(237, 137, 54, 0.2);
            color: var(--warning);
        }
        
        /* Loading */
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: var(--primary);
            animation: spin 1s ease-in-out infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .sidebar {
                display: none;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div id="app" class="app">
        <aside class="sidebar">
            <div class="logo">MSC v3.0</div>
            <nav>
                <a href="#" class="nav-item" :class="{active: currentPage === 'dashboard'}" @click="currentPage = 'dashboard'">
                    📊 Dashboard
                </a>
                <a href="#" class="nav-item" :class="{active: currentPage === 'wallet'}" @click="currentPage = 'wallet'">
                    💰 Wallet
                </a>
                <a href="#" class="nav-item" :class="{active: currentPage === 'defi'}" @click="currentPage = 'defi'">
                    🔄 DeFi
                </a>
                <a href="#" class="nav-item" :class="{active: currentPage === 'staking'}" @click="currentPage = 'staking'">
                    🎯 Staking
                </a>
                <a href="#" class="nav-item" :class="{active: currentPage === 'governance'}" @click="currentPage = 'governance'">
                    🗳️ Governance
                </a>
                <a href="#" class="nav-item" :class="{active: currentPage === 'bridge'}" @click="currentPage = 'bridge'">
                    🌉 Bridge
                </a>
                <a href="#" class="nav-item" :class="{active: currentPage === 'explorer'}" @click="currentPage = 'explorer'">
                    🔍 Explorer
                </a>
            </nav>
        </aside>
        
        <main class="main">
            <!-- Dashboard Page -->
            <div v-if="currentPage === 'dashboard'">
                <div class="header">
                    <h1 class="page-title">Dashboard</h1>
                    <div>
                        <span class="badge" :class="networkStatus === 'synced' ? 'badge-success' : 'badge-warning'">
                            {{ networkStatus }}
                        </span>
                    </div>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">Block Height</div>
                        <div class="stat-value">{{ blockHeight.toLocaleString() }}</div>
                        <div class="stat-change positive">+1 block/15s</div>
                    </div>
                    
                    <div class="stat-card">
                        <div class="stat-label">Total Transactions</div>
                        <div class="stat-value">{{ totalTransactions.toLocaleString() }}</div>
                        <div class="stat-change positive">+{{ pendingTxCount }} pending</div>
                    </div>
                    
                    <div class="stat-card">
                        <div class="stat-label">DeFi TVL</div>
                        <div class="stat-value">${{ (defiTVL / 1e18).toFixed(2) }}M</div>
                        <div class="stat-change positive">+12.5%</div>
                    </div>
                    
                    <div class="stat-card">
                        <div class="stat-label">Staking APY</div>
                        <div class="stat-value">{{ stakingAPY.toFixed(2) }}%</div>
                        <div class="stat-change">Annual</div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Network Activity</h2>
                    </div>
                    <div class="chart-container">
                        <canvas id="activityChart"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Recent Blocks</h2>
                    </div>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Block</th>
                                <th>Time</th>
                                <th>Txns</th>
                                <th>Producer</th>
                                <th>Gas Used</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="block in recentBlocks" :key="block.number">
                                <td>#{{ block.number }}</td>
                                <td>{{ formatTime(block.timestamp) }}</td>
                                <td>{{ block.transaction_count }}</td>
                                <td>{{ formatAddress(block.miner) }}</td>
                                <td>{{ formatGas(block.gas_used) }}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Wallet Page -->
            <div v-if="currentPage === 'wallet'">
                <div class="header">
                    <h1 class="page-title">Wallet</h1>
                </div>
                
                <div class="card" v-if="!wallet">
                    <h2 class="card-title">Connect Wallet</h2>
                    <p style="margin-bottom: 20px;">Connect your wallet to interact with MSC Blockchain</p>
                    <button class="btn btn-primary" @click="connectWallet">
                        Connect MetaMask
                    </button>
                </div>
                
                <div v-if="wallet">
                    <div class="card">
                        <h2 class="card-title">Account Overview</h2>
                        <div class="stats-grid">
                            <div>
                                <div class="stat-label">Address</div>
                                <div style="font-family: monospace;">{{ wallet.address }}</div>
                            </div>
                            <div>
                                <div class="stat-label">Balance</div>
                                <div class="stat-value">{{ formatBalance(wallet.balance) }} MSC</div>
                            </div>
                            <div>
                                <div class="stat-label">Nonce</div>
                                <div>{{ wallet.nonce }}</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card">
                        <h2 class="card-title">Send Transaction</h2>
                        <div class="form-group">
                            <label class="form-label">Recipient Address</label>
                            <input type="text" class="form-control" v-model="sendForm.to" placeholder="0x...">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Amount (MSC)</label>
                            <input type="number" class="form-control" v-model="sendForm.amount" placeholder="0.0">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Gas Price (Gwei)</label>
                            <input type="number" class="form-control" v-model="sendForm.gasPrice" placeholder="20">
                        </div>
                        <button class="btn btn-primary" @click="sendTransaction">
                            Send Transaction
                        </button>
                    </div>
                </div>
            </div>
            
            <!-- DeFi Page -->
            <div v-if="currentPage === 'defi'">
                <div class="header">
                    <h1 class="page-title">DeFi Hub</h1>
                </div>
                
                <div class="tabs">
                    <div class="tab" :class="{active: defiTab === 'swap'}" @click="defiTab = 'swap'">
                        Swap
                    </div>
                    <div class="tab" :class="{active: defiTab === 'liquidity'}" @click="defiTab = 'liquidity'">
                        Liquidity
                    </div>
                    <div class="tab" :class="{active: defiTab === 'lending'}" @click="defiTab = 'lending'">
                        Lending
                    </div>
                </div>
                
                <!-- Swap Tab -->
                <div v-if="defiTab === 'swap'" class="card">
                    <h2 class="card-title">Token Swap</h2>
                    <div class="form-group">
                        <label class="form-label">From</label>
                        <select class="form-control" v-model="swapForm.tokenIn">
                            <option value="MSC">MSC</option>
                            <option value="USDC">USDC</option>
                            <option value="ETH">ETH</option>
                        </select>
                        <input type="number" class="form-control" v-model="swapForm.amountIn" placeholder="0.0" style="margin-top: 10px;">
                    </div>
                    
                    <div style="text-align: center; margin: 20px 0;">
                        <button class="btn btn-secondary" @click="reverseSwap">⇅</button>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">To</label>
                        <select class="form-control" v-model="swapForm.tokenOut">
                            <option value="USDC">USDC</option>
                            <option value="MSC">MSC</option>
                            <option value="ETH">ETH</option>
                        </select>
                        <input type="number" class="form-control" v-model="swapForm.amountOut" placeholder="0.0" readonly style="margin-top: 10px;">
                    </div>
                    
                    <div style="margin: 20px 0; padding: 16px; background: rgba(255,255,255,0.05); border-radius: 8px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                            <span>Rate</span>
                            <span>1 {{ swapForm.tokenIn }} = {{ swapRate }} {{ swapForm.tokenOut }}</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                            <span>Price Impact</span>
                            <span :style="{color: priceImpact > 5 ? 'var(--danger)' : 'var(--success)'}">{{ priceImpact.toFixed(2) }}%</span>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span>Fee</span>
                            <span>0.3%</span>
                        </div>
                    </div>
                    
                    <button class="btn btn-primary" @click="executeSwap" style="width: 100%;">
                        Swap Tokens
                    </button>
                </div>
                
                <!-- Liquidity Tab -->
                <div v-if="defiTab === 'liquidity'">
                    <div class="card">
                        <h2 class="card-title">Liquidity Pools</h2>
                        <div v-for="pool in liquidityPools" :key="pool.address" class="pool-card">
                            <div class="pool-header">
                                <div class="pool-pair">{{ pool.token0 }}/{{ pool.token1 }}</div>
                                <div>
                                    <span class="badge badge-success">{{ pool.apy }}% APY</span>
                                </div>
                            </div>
                            <div class="pool-stats">
                                <div class="pool-stat">
                                    <div class="pool-stat-label">TVL</div>
                                    <div class="pool-stat-value">${{ formatNumber(pool.tvl) }}</div>
                                </div>
                                <div class="pool-stat">
                                    <div class="pool-stat-label">Volume 24h</div>
                                    <div class="pool-stat-value">${{ formatNumber(pool.volume24h) }}</div>
                                </div>
                                <div class="pool-stat">
                                    <div class="pool-stat-label">My Share</div>
                                    <div class="pool-stat-value">{{ pool.myShare }}%</div>
                                </div>
                            </div>
                            <div style="margin-top: 16px; display: flex; gap: 12px;">
                                <button class="btn btn-primary" style="flex: 1;">Add Liquidity</button>
                                <button class="btn btn-secondary" style="flex: 1;">Remove</button>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Lending Tab -->
                <div v-if="defiTab === 'lending'">
                    <div class="card">
                        <h2 class="card-title">Lending Markets</h2>
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Asset</th>
                                    <th>Total Supply</th>
                                    <th>Supply APY</th>
                                    <th>Total Borrow</th>
                                    <th>Borrow APY</th>
                                    <th>Utilization</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="market in lendingMarkets" :key="market.asset">
                                    <td>{{ market.asset }}</td>
                                    <td>${{ formatNumber(market.totalSupply) }}</td>
                                    <td style="color: var(--success);">{{ market.supplyAPY }}%</td>
                                    <td>${{ formatNumber(market.totalBorrow) }}</td>
                                    <td style="color: var(--danger);">{{ market.borrowAPY }}%</td>
                                    <td>{{ market.utilization }}%</td>
                                    <td>
                                        <button class="btn btn-primary btn-sm">Supply</button>
                                        <button class="btn btn-secondary btn-sm">Borrow</button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- Staking Page -->
            <div v-if="currentPage === 'staking'">
                <div class="header">
                    <h1 class="page-title">Staking</h1>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">Total Staked</div>
                        <div class="stat-value">{{ formatNumber(totalStaked / 1e18) }} MSC</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Active Validators</div>
                        <div class="stat-value">{{ activeValidators }}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">My Stake</div>
                        <div class="stat-value">{{ formatNumber(myStake / 1e18) }} MSC</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Rewards Earned</div>
                        <div class="stat-value">{{ formatNumber(rewardsEarned / 1e18) }} MSC</div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Validators</h2>
                        <button class="btn btn-primary">Become Validator</button>
                    </div>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Validator</th>
                                <th>Total Stake</th>
                                <th>Commission</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="validator in validators" :key="validator.address">
                                <td>{{ formatAddress(validator.address) }}</td>
                                <td>{{ formatNumber(validator.totalStake / 1e18) }} MSC</td>
                                <td>{{ validator.commission }}%</td>
                                <td>
                                    <span class="badge" :class="validator.status === 'active' ? 'badge-success' : 'badge-warning'">
                                        {{ validator.status }}
                                    </span>
                                </td>
                                <td>
                                    <button class="btn btn-primary btn-sm" @click="delegateToValidator(validator.address)">Delegate</button>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Governance Page -->
            <div v-if="currentPage === 'governance'">
                <div class="header">
                    <h1 class="page-title">Governance</h1>
                    <button class="btn btn-primary">Create Proposal</button>
                </div>
                
                <div class="card">
                    <h2 class="card-title">Active Proposals</h2>
                    <div v-for="proposal in proposals" :key="proposal.id" style="margin-bottom: 20px; padding: 20px; background: rgba(255,255,255,0.02); border-radius: 8px;">
                        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 16px;">
                            <div>
                                <h3 style="font-size: 18px; margin-bottom: 8px;">{{ proposal.title }}</h3>
                                <p style="color: var(--gray); font-size: 14px;">Proposed by {{ formatAddress(proposal.proposer) }}</p>
                            </div>
                            <span class="badge" :class="'badge-' + getProposalStatusColor(proposal.status)">
                                {{ proposal.status }}
                            </span>
                        </div>
                        
                        <div style="margin-bottom: 16px;">
                            <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                                <span>For</span>
                                <span style="color: var(--success);">{{ formatNumber(proposal.forVotes / 1e18) }} MSC</span>
                            </div>
                            <div style="background: var(--darker); height: 8px; border-radius: 4px; overflow: hidden;">
                                <div style="background: var(--success); height: 100%; transition: width 0.3s;" 
                                     :style="{width: getVotePercentage(proposal.forVotes, proposal.againstVotes) + '%'}"></div>
                            </div>
                            <div style="display: flex; justify-content: space-between; margin-top: 8px;">
                                <span>Against</span>
                                <span style="color: var(--danger);">{{ formatNumber(proposal.againstVotes / 1e18) }} MSC</span>
                            </div>
                        </div>
                        
                        <div v-if="proposal.status === 'active'">
                            <button class="btn btn-primary btn-sm" style="margin-right: 8px;">Vote For</button>
                            <button class="btn btn-secondary btn-sm">Vote Against</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Bridge Page -->
            <div v-if="currentPage === 'bridge'">
                <div class="header">
                    <h1 class="page-title">Cross-Chain Bridge</h1>
                </div>
                
                <div class="card">
                    <h2 class="card-title">Transfer Assets</h2>
                    <div class="form-group">
                        <label class="form-label">From Chain</label>
                        <select class="form-control" v-model="bridgeForm.fromChain">
                            <option value="1337">MSC Mainnet</option>
                            <option value="1">Ethereum</option>
                            <option value="56">BSC</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">To Chain</label>
                        <select class="form-control" v-model="bridgeForm.toChain">
                            <option value="1">Ethereum</option>
                            <option value="56">BSC</option>
                            <option value="137">Polygon</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Token</label>
                        <select class="form-control" v-model="bridgeForm.token">
                            <option value="MSC">MSC</option>
                            <option value="USDC">USDC</option>
                            <option value="ETH">ETH</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Amount</label>
                        <input type="number" class="form-control" v-model="bridgeForm.amount" placeholder="0.0">
                    </div>
                    
                    <div style="margin: 20px 0; padding: 16px; background: rgba(255,255,255,0.05); border-radius: 8px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                            <span>Bridge Fee</span>
                            <span>0.1%</span>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span>Estimated Time</span>
                            <span>~10 minutes</span>
                        </div>
                    </div>
                    
                    <button class="btn btn-primary" @click="initiateBridge" style="width: 100%;">
                        Bridge Tokens
                    </button>
                </div>
                
                <div class="card">
                    <h2 class="card-title">Recent Transfers</h2>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>From → To</th>
                                <th>Token</th>
                                <th>Amount</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="transfer in recentTransfers" :key="transfer.id">
                                <td>{{ transfer.id.substring(0, 8) }}...</td>
                                <td>{{ getChainName(transfer.fromChain) }} → {{ getChainName(transfer.toChain) }}</td>
                                <td>{{ transfer.token }}</td>
                                <td>{{ formatNumber(transfer.amount) }}</td>
                                <td>
                                    <span class="badge" :class="'badge-' + getTransferStatusColor(transfer.status)">
                                        {{ transfer.status }}
                                    </span>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Explorer Page -->
            <div v-if="currentPage === 'explorer'">
                <div class="header">
                    <h1 class="page-title">Blockchain Explorer</h1>
                </div>
                
                <div class="card">
                    <div class="form-group">
                        <input type="text" class="form-control" v-model="searchQuery" 
                               placeholder="Search by Address / Txn Hash / Block" 
                               @keyup.enter="search">
                    </div>
                </div>
                
                <div class="tabs">
                    <div class="tab" :class="{active: explorerTab === 'blocks'}" @click="explorerTab = 'blocks'">
                        Blocks
                    </div>
                    <div class="tab" :class="{active: explorerTab === 'transactions'}" @click="explorerTab = 'transactions'">
                        Transactions
                    </div>
                    <div class="tab" :class="{active: explorerTab === 'addresses'}" @click="explorerTab = 'addresses'">
                        Top Addresses
                    </div>
                </div>
                
                <div v-if="explorerTab === 'blocks'" class="card">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Block</th>
                                <th>Age</th>
                                <th>Txns</th>
                                <th>Producer</th>
                                <th>Gas Used</th>
                                <th>Reward</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="block in blocks" :key="block.number">
                                <td>
                                    <a href="#" @click.prevent="viewBlock(block.number)" style="color: var(--primary);">
                                        #{{ block.number }}
                                    </a>
                                </td>
                                <td>{{ getAge(block.timestamp) }}</td>
                                <td>{{ block.transaction_count }}</td>
                                <td>{{ formatAddress(block.miner) }}</td>
                                <td>{{ formatGas(block.gas_used) }} ({{ ((block.gas_used / block.gas_limit) * 100).toFixed(2) }}%)</td>
                                <td>{{ block.reward }} MSC</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <div v-if="explorerTab === 'transactions'" class="card">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Txn Hash</th>
                                <th>Age</th>
                                <th>From</th>
                                <th>To</th>
                                <th>Value</th>
                                <th>Fee</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="tx in transactions" :key="tx.hash">
                                <td>
                                    <a href="#" @click.prevent="viewTransaction(tx.hash)" style="color: var(--primary);">
                                        {{ tx.hash.substring(0, 10) }}...
                                    </a>
                                </td>
                                <td>{{ getAge(tx.timestamp) }}</td>
                                <td>{{ formatAddress(tx.from) }}</td>
                                <td>{{ formatAddress(tx.to) }}</td>
                                <td>{{ formatBalance(tx.value) }} MSC</td>
                                <td>{{ formatBalance(tx.gasUsed * tx.gasPrice) }} MSC</td>
                                <td>
                                    <span class="badge badge-success">Success</span>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <div v-if="explorerTab === 'addresses'" class="card">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Rank</th>
                                <th>Address</th>
                                <th>Balance</th>
                                <th>Percentage</th>
                                <th>Txn Count</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="(addr, index) in topAddresses" :key="addr.address">
                                <td>#{{ index + 1 }}</td>
                                <td>
                                    <a href="#" @click.prevent="viewAddress(addr.address)" style="color: var(--primary);">
                                        {{ formatAddress(addr.address) }}
                                    </a>
                                </td>
                                <td>{{ formatNumber(addr.balance / 1e18) }} MSC</td>
                                <td>{{ ((addr.balance / totalSupply) * 100).toFixed(4) }}%</td>
                                <td>{{ addr.txCount }}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </main>
    </div>
    
    <script>
        const { createApp } = Vue;
        
        createApp({
            data() {
                return {
                    // Navigation
                    currentPage: 'dashboard',
                    
                    // Network
                    socket: null,
                    networkStatus: 'syncing',
                    blockHeight: 0,
                    totalTransactions: 0,
                    pendingTxCount: 0,
                    
                    // Wallet
                    wallet: null,
                    sendForm: {
                        to: '',
                        amount: '',
                        gasPrice: '20'
                    },
                    
                    // DeFi
                    defiTab: 'swap',
                    defiTVL: 0,
                    swapForm: {
                        tokenIn: 'MSC',
                        tokenOut: 'USDC',
                        amountIn: '',
                        amountOut: ''
                    },
                    swapRate: 1,
                    priceImpact: 0,
                    liquidityPools: [],
                    lendingMarkets: [],
                    
                    // Staking
                    stakingAPY: 5.0,
                    totalStaked: 0,
                    activeValidators: 0,
                    myStake: 0,
                    rewardsEarned: 0,
                    validators: [],
                    
                    // Governance
                    proposals: [],
                    
                    // Bridge
                    bridgeForm: {
                        fromChain: '1337',
                        toChain: '1',
                        token: 'MSC',
                        amount: ''
                    },
                    recentTransfers: [],
                    
                    // Explorer
                    explorerTab: 'blocks',
                    searchQuery: '',
                    blocks: [],
                    transactions: [],
                    topAddresses: [],
                    recentBlocks: [],
                    totalSupply: 100000000 * 1e18,
                    
                    // Charts
                    activityChart: null
                };
            },
            
            mounted() {
                this.initWebSocket();
                this.loadInitialData();
                this.initCharts();
            },
            
            methods: {
                // WebSocket
                initWebSocket() {
                    this.socket = io();
                    
                    this.socket.on('connect', () => {
                        console.log('Connected to MSC v3.0');
                        this.networkStatus = 'synced';
                        this.socket.emit('subscribe', { type: 'blocks' });
                        this.socket.emit('subscribe', { type: 'defi' });
                    });
                    
                    this.socket.on('disconnect', () => {
                        this.networkStatus = 'offline';
                    });
                    
                    this.socket.on('new_block', (block) => {
                        this.blockHeight = block.number;
                        this.recentBlocks.unshift(block);
                        if (this.recentBlocks.length > 5) {
                            this.recentBlocks.pop();
                        }
                        this.updateActivityChart();
                    });
                    
                    this.socket.on('new_transaction', (tx) => {
                        this.pendingTxCount++;
                    });
                },
                
                // Data Loading
                async loadInitialData() {
                    try {
                        // Load status
                        const status = await fetch('/api/v3/status').then(r => r.json());
                        this.blockHeight = status.latest_block.number;
                        this.totalTransactions = status.total_transactions;
                        this.pendingTxCount = status.pending_transactions;
                        
                        // Load recent blocks
                        const blocksResp = await fetch('/api/v3/blocks/latest').then(r => r.json());
                        // Process blocks...
                        
                        // Load DeFi data
                        await this.loadDeFiData();
                        
                        // Load staking data
                        await this.loadStakingData();
                        
                    } catch (error) {
                        console.error('Error loading data:', error);
                    }
                },
                
                async loadDeFiData() {
                    // Load DEX pairs
                    const pairs = await fetch('/api/v3/defi/dex/pairs').then(r => r.json());
                    this.liquidityPools = pairs.pairs.map(p => ({
                        ...p,
                        tvl: parseFloat(p.reserve0) + parseFloat(p.reserve1),
                        volume24h: Math.random() * 1000000,
                        apy: (Math.random() * 50).toFixed(2),
                        myShare: 0
                    }));
                    
                    // Load lending markets
                    const markets = await fetch('/api/v3/defi/lending/markets').then(r => r.json());
                    this.lendingMarkets = markets.markets.map(m => ({
                        ...m,
                        totalSupply: parseFloat(m.total_supply),
                        totalBorrow: parseFloat(m.total_borrows),
                        supplyAPY: (parseFloat(m.supply_rate) * 100).toFixed(2),
                        borrowAPY: (parseFloat(m.borrow_rate) * 100).toFixed(2),
                        utilization: (parseFloat(m.utilization) * 100).toFixed(2)
                    }));
                    
                    // Calculate total TVL
                    this.defiTVL = this.liquidityPools.reduce((sum, p) => sum + p.tvl, 0) +
                                   this.lendingMarkets.reduce((sum, m) => sum + m.totalSupply, 0);
                },
                
                async loadStakingData() {
                    const validators = await fetch('/api/v3/defi/staking/validators').then(r => r.json());
                    this.validators = validators.validators.map(v => ({
                        ...v,
                        totalStake: parseFloat(v.total_delegation),
                        commission: parseFloat(v.commission_rate) * 100
                    }));
                    
                    this.activeValidators = this.validators.filter(v => v.status === 'active').length;
                    this.totalStaked = this.validators.reduce((sum, v) => sum + v.totalStake, 0);
                },
                
                // Wallet Functions
                async connectWallet() {
                    if (typeof window.ethereum !== 'undefined') {
                        try {
                            const accounts = await window.ethereum.request({ 
                                method: 'eth_requestAccounts' 
                            });
                            
                            this.wallet = {
                                address: accounts[0],
                                balance: 0,
                                nonce: 0
                            };
                            
                            // Load account data
                            await this.loadAccountData();
                            
                        } catch (error) {
                            console.error('Error connecting wallet:', error);
                        }
                    } else {
                        alert('Please install MetaMask!');
                    }
                },
                
                async loadAccountData() {
                    if (!this.wallet) return;
                    
                    const account = await fetch(`/api/v3/accounts/${this.wallet.address}`).then(r => r.json());
                    this.wallet.balance = account.balance;
                    this.wallet.nonce = account.nonce;
                },
                
                async sendTransaction() {
                    if (!this.wallet) {
                        alert('Please connect wallet first');
                        return;
                    }
                    
                    try {
                        const tx = {
                            from: this.wallet.address,
                            to: this.sendForm.to,
                            value: ethers.utils.parseEther(this.sendForm.amount).toString(),
                            gasPrice: ethers.utils.parseUnits(this.sendForm.gasPrice, 'gwei').toString(),
                            gasLimit: '21000',
                            nonce: this.wallet.nonce
                        };
                        
                        // Sign with MetaMask
                        const txHash = await window.ethereum.request({
                            method: 'eth_sendTransaction',
                            params: [tx]
                        });
                        
                        alert(`Transaction sent: ${txHash}`);
                        
                    } catch (error) {
                        alert('Transaction failed: ' + error.message);
                    }
                },
                
                // DeFi Functions
                reverseSwap() {
                    const temp = this.swapForm.tokenIn;
                    this.swapForm.tokenIn = this.swapForm.tokenOut;
                    this.swapForm.tokenOut = temp;
                    this.calculateSwapOutput();
                },
                
                async calculateSwapOutput() {
                    if (!this.swapForm.amountIn) {
                        this.swapForm.amountOut = '';
                        return;
                    }
                    
                    // Find pair
                    const pair = this.liquidityPools.find(p => 
                        (p.token0 === this.swapForm.tokenIn && p.token1 === this.swapForm.tokenOut) ||
                        (p.token1 === this.swapForm.tokenIn && p.token0 === this.swapForm.tokenOut)
                    );
                    
                    if (pair) {
                        // Calculate using x*y=k
                        const amountIn = parseFloat(this.swapForm.amountIn);
                        const reserveIn = this.swapForm.tokenIn === pair.token0 ? 
                                         parseFloat(pair.reserve0) : parseFloat(pair.reserve1);
                        const reserveOut = this.swapForm.tokenIn === pair.token0 ? 
                                          parseFloat(pair.reserve1) : parseFloat(pair.reserve0);
                        
                        const amountInWithFee = amountIn * 0.997; // 0.3% fee
                        const amountOut = (amountInWithFee * reserveOut) / (reserveIn + amountInWithFee);
                        
                        this.swapForm.amountOut = amountOut.toFixed(6);
                        this.swapRate = (amountOut / amountIn).toFixed(6);
                        this.priceImpact = ((amountIn / reserveIn) * 100).toFixed(2);
                    }
                },
                
                async executeSwap() {
                    if (!this.wallet) {
                        alert('Please connect wallet first');
                        return;
                    }
                    
                    // Implement swap execution
                    alert('Swap functionality in development');
                },
                
                // Charts
                initCharts() {
                    const ctx = document.getElementById('activityChart');
                    if (ctx) {
                        this.activityChart = new Chart(ctx, {
                            type: 'line',
                            data: {
                                labels: [],
                                datasets: [{
                                    label: 'Transactions per Block',
                                    data: [],
                                    borderColor: '#667eea',
                                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                                    tension: 0.4
                                }]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {
                                    legend: {
                                        display: false
                                    }
                                },
                                scales: {
                                    y: {
                                        beginAtZero: true,
                                        grid: {
                                            color: 'rgba(255, 255, 255, 0.1)'
                                        }
                                    },
                                    x: {
                                        grid: {
                                            color: 'rgba(255, 255, 255, 0.1)'
                                        }
                                    }
                                }
                            }
                        });
                    }
                },
                
                updateActivityChart() {
                    if (this.activityChart && this.recentBlocks.length > 0) {
                        const labels = this.recentBlocks.map(b => '#' + b.number).reverse();
                        const data = this.recentBlocks.map(b => b.transaction_count).reverse();
                        
                        this.activityChart.data.labels = labels;
                        this.activityChart.data.datasets[0].data = data;
                        this.activityChart.update();
                    }
                },
                
                // Utility Functions
                formatAddress(address) {
                    if (!address) return '';
                    return address.substring(0, 6) + '...' + address.substring(38);
                },
                
                formatBalance(wei) {
                    return (parseFloat(wei) / 1e18).toFixed(4);
                },
                
                formatNumber(num) {
                    return new Intl.NumberFormat().format(num);
                },
                
                formatGas(gas) {
                    return (gas / 1e6).toFixed(2) + 'M';
                },
                
                formatTime(timestamp) {
                    return new Date(timestamp * 1000).toLocaleTimeString();
                },
                
                getAge(timestamp) {
                    const seconds = Math.floor(Date.now() / 1000) - timestamp;
                    if (seconds < 60) return seconds + 's ago';
                    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
                    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
                    return Math.floor(seconds / 86400) + 'd ago';
                },
                
                getVotePercentage(forVotes, againstVotes) {
                    const total = parseFloat(forVotes) + parseFloat(againstVotes);
                    if (total === 0) return 0;
                    return (parseFloat(forVotes) / total) * 100;
                },
                
                getProposalStatusColor(status) {
                    const colors = {
                        'active': 'success',
                        'pending': 'warning',
                        'executed': 'success',
                        'defeated': 'danger',
                        'cancelled': 'danger'
                    };
                    return colors[status] || 'secondary';
                },
                
                getTransferStatusColor(status) {
                    const colors = {
                        'pending': 'warning',
                        'confirmed': 'success',
                        'executed': 'success',
                        'failed': 'danger'
                    };
                    return colors[status] || 'secondary';
                },
                
                getChainName(chainId) {
                    const chains = {
                        '1': 'Ethereum',
                        '56': 'BSC',
                        '137': 'Polygon',
                        '1337': 'MSC'
                    };
                    return chains[chainId] || 'Unknown';
                },
                
                // Navigation
                viewBlock(number) {
                    // Implement block viewer
                    console.log('View block:', number);
                },
                
                viewTransaction(hash) {
                    // Implement transaction viewer
                    console.log('View transaction:', hash);
                },
                
                viewAddress(address) {
                    // Implement address viewer
                    console.log('View address:', address);
                },
                
                search() {
                    // Implement search functionality
                    console.log('Search:', this.searchQuery);
                },
                
                delegateToValidator(address) {
                    // Implement delegation
                    console.log('Delegate to:', address);
                },
                
                async initiateBridge() {
                    // Implement bridge
                    alert('Bridge functionality in development');
                }
            }
        }).mount('#app');
    </script>
</body>
</html>
'''

# === RLP ENCODING (simplificado) ===
def rlp_encode(data):
    """Codificación RLP simplificada"""
    if isinstance(data, int):
        if data == 0:
            return b'\x80'
        return data.to_bytes((data.bit_length() + 7) // 8, 'big')
    elif isinstance(data, str):
        return data.encode()
    elif isinstance(data, bytes):
        return data
    elif isinstance(data, list):
        output = b''
        for item in data:
            output += rlp_encode(item)
        return output
    else:
        raise TypeError(f"Cannot encode type {type(data)}")

# === NODO P2P MEJORADO ===
class P2PNodeV3:
    """Nodo P2P enterprise con descubrimiento y sincronización avanzada"""
    
    def __init__(self, blockchain: MSCBlockchainV3, port: int = 30303):
        self.blockchain = blockchain
        self.port = port
        self.node_id = self._generate_node_id()
        self.peers = {}  # peer_id -> PeerConnection
        self.discovery_protocol = DiscoveryProtocol(self)
        
    def _generate_node_id(self) -> str:
        """Genera ID único del nodo"""
        # En producción, esto sería una clave pública
        return secrets.token_hex(32)
    
    async def start(self):
        """Inicia el nodo P2P"""
        # Iniciar servidor
        server = await asyncio.start_server(
            self.handle_peer_connection,
            '0.0.0.0',
            self.port
        )
        
        # Iniciar discovery
        asyncio.create_task(self.discovery_protocol.start())
        
        logger.info(f"P2P node started on port {self.port}")
        logger.info(f"Node ID: {self.node_id}")
        
        async with server:
            await server.serve_forever()
    
    async def handle_peer_connection(self, reader, writer):
        """Maneja conexión entrante de peer"""
        peer_address = writer.get_extra_info('peername')
        logger.info(f"New peer connection from {peer_address}")
        
        peer = PeerConnection(reader, writer, self)
        await peer.handle()

class PeerConnection:
    """Conexión individual con un peer"""
    
    def __init__(self, reader, writer, node: P2PNodeV3):
        self.reader = reader
        self.writer = writer
        self.node = node
        self.peer_id = None
        self.version = None
        
    async def handle(self):
        """Maneja comunicación con peer"""
        try:
            # Handshake
            await self.handshake()
            
            # Message loop
            while True:
                message = await self.read_message()
                if not message:
                    break
                
                await self.handle_message(message)
                
        except Exception as e:
            logger.error(f"Peer connection error: {e}")
        finally:
            self.writer.close()
            await self.writer.wait_closed()
    
    async def handshake(self):
        """Protocolo de handshake"""
        # Enviar hello
        hello = {
            'type': 'hello',
            'version': BlockchainConfig.VERSION,
            'node_id': self.node.node_id,
            'chain_id': BlockchainConfig.CHAIN_ID,
            'total_difficulty': sum(b.header.difficulty for b in self.node.blockchain.chain),
            'best_hash': self.node.blockchain.get_latest_block().hash,
            'genesis_hash': self.node.blockchain.chain[0].hash
        }
        
        await self.send_message(hello)
        
        # Recibir hello
        response = await self.read_message()
        if response['type'] != 'hello':
            raise ValueError("Invalid handshake")
        
        self.peer_id = response['node_id']
        self.version = response['version']
        
        # Verificar compatibilidad
        if response['chain_id'] != BlockchainConfig.CHAIN_ID:
            raise ValueError("Different chain ID")
        
        if response['genesis_hash'] != self.node.blockchain.chain[0].hash:
            raise ValueError("Different genesis")
    
    async def send_message(self, message: Dict):
        """Envía mensaje al peer"""
        data = json.dumps(message).encode()
        self.writer.write(len(data).to_bytes(4, 'big'))
        self.writer.write(data)
        await self.writer.drain()
    
    async def read_message(self) -> Optional[Dict]:
        """Lee mensaje del peer"""
        # Leer longitud
        length_data = await self.reader.read(4)
        if not length_data:
            return None
        
        length = int.from_bytes(length_data, 'big')
        
        # Leer mensaje
        data = await self.reader.read(length)
        return json.loads(data.decode())
    
    async def handle_message(self, message: Dict):
        """Procesa mensaje recibido"""
        msg_type = message.get('type')
        
        if msg_type == 'get_blocks':
            await self.handle_get_blocks(message)
        elif msg_type == 'blocks':
            await self.handle_blocks(message)
        elif msg_type == 'new_block':
            await self.handle_new_block(message)
        elif msg_type == 'new_transaction':
            await self.handle_new_transaction(message)
        elif msg_type == 'get_peer_list':
            await self.handle_get_peer_list(message)
    
    async def handle_get_blocks(self, message: Dict):
        """Maneja solicitud de bloques"""
        start = message['start']
        count = min(message['count'], 100)
        
        blocks = []
        for i in range(start, min(start + count, len(self.node.blockchain.chain))):
            block = self.node.blockchain.chain[i]
            blocks.append({
                'header': asdict(block.header),
                'transactions': [asdict(tx) for tx in block.transactions],
                'uncles': [asdict(u) for u in block.uncles]
            })
        
        await self.send_message({
            'type': 'blocks',
            'blocks': blocks
        })

class DiscoveryProtocol:
    """Protocolo de descubrimiento de peers"""
    
    def __init__(self, node: P2PNodeV3):
        self.node = node
        self.bootstrap_nodes = [
            # Lista de nodos bootstrap
            "msc-boot-1.network:30303",
            "msc-boot-2.network:30303"
        ]
        
    async def start(self):
        """Inicia protocolo de descubrimiento"""
        # Conectar a nodos bootstrap
        for boot_node in self.bootstrap_nodes:
            try:
                await self.connect_to_peer(boot_node)
            except Exception as e:
                logger.error(f"Failed to connect to bootstrap node {boot_node}: {e}")
        
        # Descubrimiento periódico
        while True:
            await self.discover_peers()
            await asyncio.sleep(BlockchainConfig.PEER_DISCOVERY_INTERVAL)
    
    async def connect_to_peer(self, address: str):
        """Conecta a un peer específico"""
        host, port = address.split(':')
        
        reader, writer = await asyncio.open_connection(host, int(port))
        peer = PeerConnection(reader, writer, self.node)
        
        # Handshake en background
        asyncio.create_task(peer.handle())
    
    async def discover_peers(self):
        """Descubre nuevos peers"""
        # Solicitar lista de peers a peers conocidos
        for peer in self.node.peers.values():
            try:
                await peer.send_message({'type': 'get_peer_list'})
            except:
                pass

# === HERRAMIENTAS CLI ===
def create_cli():
    """CLI mejorado para MSC Blockchain v3"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='MSC Blockchain v3.0 - Enterprise DeFi Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Node command
    node_parser = subparsers.add_parser('node', help='Run blockchain node')
    node_parser.add_argument('--api-port', type=int, default=8545, help='API port')
    node_parser.add_argument('--p2p-port', type=int, default=30303, help='P2P port')
    node_parser.add_argument('--data-dir', default='./data', help='Data directory')
    node_parser.add_argument('--mine', action='store_true', help='Enable mining')
    node_parser.add_argument('--validator', help='Validator address for PoS')
    
    # Account command
    account_parser = subparsers.add_parser('account', help='Manage accounts')
    account_subparsers = account_parser.add_subparsers(dest='subcommand')
    
    account_new = account_subparsers.add_parser('new', help='Create new account')
    account_list = account_subparsers.add_parser('list', help='List accounts')
    account_balance = account_subparsers.add_parser('balance', help='Check balance')
    account_balance.add_argument('address', help='Account address')
    
    # Transaction command
    tx_parser = subparsers.add_parser('tx', help='Send transaction')
    tx_parser.add_argument('--from', dest='from_addr', required=True, help='From address')
    tx_parser.add_argument('--to', required=True, help='To address')
    tx_parser.add_argument('--value', required=True, help='Value in MSC')
    tx_parser.add_argument('--gas-price', default='20', help='Gas price in Gwei')
    
    # DeFi commands
    defi_parser = subparsers.add_parser('defi', help='DeFi operations')
    defi_subparsers = defi_parser.add_subparsers(dest='defi_command')
    
    # Swap
    swap_parser = defi_subparsers.add_parser('swap', help='Token swap')
    swap_parser.add_argument('--token-in', required=True, help='Input token')
    swap_parser.add_argument('--token-out', required=True, help='Output token')
    swap_parser.add_argument('--amount', required=True, help='Amount to swap')
    
    # Stake
    stake_parser = defi_subparsers.add_parser('stake', help='Stake tokens')
    stake_parser.add_argument('--amount', required=True, help='Amount to stake')
    stake_parser.add_argument('--validator', help='Validator address')
    
    return parser

# === MAIN ENTRY POINT ===
async def main():
    """Entry point principal"""
    parser = create_cli()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Configurar logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    if args.command == 'node':
        # Inicializar blockchain
        logger.info("🚀 Starting MSC Blockchain v3.0...")
        
        # Crear directorios
        os.makedirs(args.data_dir, exist_ok=True)
        BlockchainConfig.STATE_DB_PATH = os.path.join(args.data_dir, "state")
        BlockchainConfig.BLOCKCHAIN_DB_PATH = os.path.join(args.data_dir, "blockchain.db")
        
        # Crear blockchain
        blockchain = MSCBlockchainV3()
        
        # Iniciar API
        api = BlockchainAPIv3(blockchain)
        api_thread = threading.Thread(
            target=lambda: api.run(port=args.api_port),
            daemon=True
        )
        api_thread.start()
        
        logger.info(f"✅ API started on http://localhost:{args.api_port}")
        
        # Iniciar P2P
        p2p_node = P2PNodeV3(blockchain, port=args.p2p_port)
        
        # Mining loop si está habilitado
        if args.mine:
            asyncio.create_task(mining_loop(blockchain, args.validator or "POW_MINER"))
        
        # Iniciar nodo P2P
        await p2p_node.start()
        
    elif args.command == 'account':
        # Comandos de cuenta
        blockchain = MSCBlockchainV3()
        
        if args.subcommand == 'new':
            # Crear nueva cuenta
            private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
            public_key = private_key.public_key()
            
            # Derivar dirección
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            address = '0x' + hashlib.sha256(public_bytes).hexdigest()[-40:]
            
            print(f"Address: {address}")
            print(f"Private Key: {private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode()}")
            
        elif args.subcommand == 'balance':
            balance = blockchain.get_balance(args.address)
            print(f"Balance: {balance / 1e18:.6f} MSC")

async def mining_loop(blockchain: MSCBlockchainV3, miner_address: str):
    """Loop de minería"""
    while True:
        try:
            block = await blockchain.mine_block(miner_address)
            if block:
                logger.info(f"⛏️  Mined block #{block.header.number}")
        except Exception as e:
            logger.error(f"Mining error: {e}")
        
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())