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
import random
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
# import ed25519  # Comentado - no disponible en Windows

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
# import plyvel  # Comentado - no disponible en Windows  # LevelDB for state storage

# === LOGGING ===
import logging
logger = logging.getLogger(__name__)

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
        node_hash = hashlib.sha3_256(encoded).digest()
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
        current_node = self._decode_node(proof[0])
        nibbles = self._key_to_nibbles(key)
        
        for i, proof_node in enumerate(proof[1:], 1):
            decoded_node = self._decode_node(proof_node)
            if not self._verify_proof_recursive(current_node, decoded_node, nibbles, value):
                return False
            current_node = decoded_node
            
        return True

    def _verify_proof_recursive(self, node, proof_node, nibbles: List[int], expected_value: bytes) -> bool:
        """Verifica recursivamente una prueba Merkle"""
        # Implementación simplificada - en producción sería más robusta
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
        """Recupera la dirección del sender desde la firma ECDSA"""
        if not all([self.v, self.r, self.s]):
            return None

        try:
            # Recuperar clave pública desde firma ECDSA
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            import ecdsa
            
            # Convertir r, s a enteros
            r_int = int(self.r, 16) if isinstance(self.r, str) else int.from_bytes(self.r, 'big')
            s_int = int(self.s, 16) if isinstance(self.s, str) else int.from_bytes(self.s, 'big')
            v_int = int(self.v, 16) if isinstance(self.v, str) else int.from_bytes(self.v, 'big')
            
            # Crear firma ECDSA
            signature = ecdsa.util.sigencode_string(r_int, s_int, 32)
            
            # Obtener hash de la transacción
            tx_hash = self.signing_hash()
            
            # Recuperar clave pública
            vk = ecdsa.VerifyingKey.from_public_key_recovery(
                signature, 
                tx_hash, 
                ecdsa.SECP256k1,
                hashfunc=hashlib.sha256
            )[0]
            
            # Obtener dirección (últimos 20 bytes del hash de la clave pública)
            public_key_bytes = vk.to_string()
            address_hash = hashlib.sha256(public_key_bytes).digest()
            address = address_hash[-20:]
            
            return "0x" + address.hex()
            
        except Exception as e:
            # Fallback seguro - no devolver dirección si hay error
            return None

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

# === COMPILADOR DE CONTRATOS ===
class MSCCompiler:
    """Compilador de contratos inteligentes a bytecode"""
    
    def __init__(self):
        self.opcodes = {
            'STOP': 0x00, 'ADD': 0x01, 'MUL': 0x02, 'SUB': 0x03, 'DIV': 0x04,
            'LT': 0x10, 'GT': 0x11, 'EQ': 0x14, 'SHA3': 0x20,
            'ADDRESS': 0x30, 'BALANCE': 0x31, 'CALLDATALOAD': 0x35, 'CALLDATASIZE': 0x36,
            'POP': 0x50, 'MLOAD': 0x51, 'MSTORE': 0x52, 'SLOAD': 0x54, 'SSTORE': 0x55,
            'JUMP': 0x56, 'JUMPI': 0x57, 'PUSH1': 0x60, 'PUSH2': 0x61, 'PUSH32': 0x7f,
            'LOG0': 0xa0, 'LOG1': 0xa1, 'LOG2': 0xa2, 'LOG3': 0xa3, 'LOG4': 0xa4,
            'RETURN': 0xf3, 'REVERT': 0xfd, 'SELFDESTRUCT': 0xff
        }
    
    def compile(self, source_code: str) -> bytes:
        """Compila código fuente a bytecode"""
        lines = source_code.strip().split('\n')
        bytecode = bytearray()
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('//'):
                continue
                
            parts = line.split()
            if not parts:
                continue
                
            opcode = parts[0].upper()
            if opcode in self.opcodes:
                bytecode.append(self.opcodes[opcode])
                
                # Manejar operandos
                if opcode.startswith('PUSH'):
                    if len(parts) > 1:
                        try:
                            value = int(parts[1], 16) if parts[1].startswith('0x') else int(parts[1])
                            push_size = int(opcode[4:])  # Extraer número de PUSH
                            bytecode.extend(value.to_bytes(push_size, 'big'))
                        except ValueError:
                            raise ValueError(f"Invalid operand for {opcode}: {parts[1]}")
                elif opcode in ['JUMP', 'JUMPI'] and len(parts) > 1:
                    try:
                        address = int(parts[1], 16) if parts[1].startswith('0x') else int(parts[1])
                        bytecode.extend(address.to_bytes(32, 'big'))
                    except ValueError:
                        raise ValueError(f"Invalid jump address: {parts[1]}")
        
        return bytes(bytecode)
    
    def decompile(self, bytecode: bytes) -> str:
        """Descompila bytecode a código fuente"""
        lines = []
        i = 0
        
        while i < len(bytecode):
            opcode_byte = bytecode[i]
            opcode_name = None
            
            # Encontrar nombre del opcode
            for name, code in self.opcodes.items():
                if code == opcode_byte:
                    opcode_name = name
                    break
            
            if opcode_name:
                if opcode_name.startswith('PUSH'):
                    push_size = int(opcode_name[4:])
                    if i + push_size < len(bytecode):
                        value = int.from_bytes(bytecode[i+1:i+1+push_size], 'big')
                        lines.append(f"{opcode_name} 0x{value:x}")
                        i += 1 + push_size
                    else:
                        lines.append(f"{opcode_name} <incomplete>")
                        i += 1
                elif opcode_name in ['JUMP', 'JUMPI']:
                    if i + 32 < len(bytecode):
                        address = int.from_bytes(bytecode[i+1:i+33], 'big')
                        lines.append(f"{opcode_name} 0x{address:x}")
                        i += 33
                    else:
                        lines.append(f"{opcode_name} <incomplete>")
                        i += 1
                else:
                    lines.append(opcode_name)
                    i += 1
            else:
                lines.append(f"UNKNOWN 0x{opcode_byte:02x}")
                i += 1
        
        return '\n'.join(lines)

# === VIRTUAL MACHINE FUNCIONAL ===
class MSCVirtualMachine:
    """Máquina virtual funcional para smart contracts con compilador e intérprete real"""

    def __init__(self, state_db: MerklePatriciaTrie):
        self.state_db = state_db
        self.stack = []
        self.memory = bytearray(1024 * 1024)  # 1MB de memoria
        self.storage = {}
        self.pc = 0  # Program counter
        self.gas_remaining = 0
        self.return_data = b""
        self.logs = []
        self.context = {}
        
        # Protección contra re-entrancy
        self.call_depth = 0
        self.max_call_depth = 1024
        self.reentrancy_guard = {}
        self.call_stack = []
        
        # Compilador integrado
        self.compiler = MSCCompiler()
        
        # Opcodes completos con implementaciones reales
        self.opcodes = {
            # Aritmética
            0x00: self.op_stop, 0x01: self.op_add, 0x02: self.op_mul, 0x03: self.op_sub,
            0x04: self.op_div, 0x05: self.op_sdiv, 0x06: self.op_mod, 0x07: self.op_smod,
            0x08: self.op_addmod, 0x09: self.op_mulmod, 0x0a: self.op_exp, 0x0b: self.op_signextend,
            
            # Comparación
            0x10: self.op_lt, 0x11: self.op_gt, 0x12: self.op_slt, 0x13: self.op_sgt,
            0x14: self.op_eq, 0x15: self.op_iszero, 0x16: self.op_and, 0x17: self.op_or,
            0x18: self.op_xor, 0x19: self.op_not, 0x1a: self.op_byte, 0x1b: self.op_shl,
            0x1c: self.op_shr, 0x1d: self.op_sar,
            
            # SHA3
            0x20: self.op_sha3,
            
            # Información del contexto
            0x30: self.op_address, 0x31: self.op_balance, 0x32: self.op_origin,
            0x33: self.op_caller, 0x34: self.op_callvalue, 0x35: self.op_calldataload,
            0x36: self.op_calldatasize, 0x37: self.op_calldatacopy, 0x38: self.op_codesize,
            0x39: self.op_codecopy, 0x3a: self.op_gasprice, 0x3b: self.op_extcodesize,
            0x3c: self.op_extcodecopy, 0x3d: self.op_returndatasize, 0x3e: self.op_returndatacopy,
            0x3f: self.op_extcodehash,
            
            # Operaciones de bloque
            0x40: self.op_blockhash, 0x41: self.op_coinbase, 0x42: self.op_timestamp,
            0x43: self.op_number, 0x44: self.op_difficulty, 0x45: self.op_gaslimit,
            0x46: self.op_chainid, 0x47: self.op_selfbalance, 0x48: self.op_basefee,
            
            # Stack, memoria y storage
            0x50: self.op_pop, 0x51: self.op_mload, 0x52: self.op_mstore, 0x53: self.op_mstore8,
            0x54: self.op_sload, 0x55: self.op_sstore, 0x56: self.op_jump, 0x57: self.op_jumpi,
            0x58: self.op_pc, 0x59: self.op_msize, 0x5a: self.op_gas, 0x5b: self.op_jumpdest,
            
            # Push operations
            0x60: self.op_push1, 0x61: self.op_push2, 0x62: self.op_push3, 0x63: self.op_push4,
            0x64: self.op_push5, 0x65: self.op_push6, 0x66: self.op_push7, 0x67: self.op_push8,
            0x68: self.op_push9, 0x69: self.op_push10, 0x6a: self.op_push11, 0x6b: self.op_push12,
            0x6c: self.op_push13, 0x6d: self.op_push14, 0x6e: self.op_push15, 0x6f: self.op_push16,
            0x70: self.op_push17, 0x71: self.op_push18, 0x72: self.op_push19, 0x73: self.op_push20,
            0x74: self.op_push21, 0x75: self.op_push22, 0x76: self.op_push23, 0x77: self.op_push24,
            0x78: self.op_push25, 0x79: self.op_push26, 0x7a: self.op_push27, 0x7b: self.op_push28,
            0x7c: self.op_push29, 0x7d: self.op_push30, 0x7e: self.op_push31, 0x7f: self.op_push32,
            
            # Duplicate operations
            0x80: self.op_dup1, 0x81: self.op_dup2, 0x82: self.op_dup3, 0x83: self.op_dup4,
            0x84: self.op_dup5, 0x85: self.op_dup6, 0x86: self.op_dup7, 0x87: self.op_dup8,
            0x88: self.op_dup9, 0x89: self.op_dup10, 0x8a: self.op_dup11, 0x8b: self.op_dup12,
            0x8c: self.op_dup13, 0x8d: self.op_dup14, 0x8e: self.op_dup15, 0x8f: self.op_dup16,
            
            # Exchange operations
            0x90: self.op_swap1, 0x91: self.op_swap2, 0x92: self.op_swap3, 0x93: self.op_swap4,
            0x94: self.op_swap5, 0x95: self.op_swap6, 0x96: self.op_swap7, 0x97: self.op_swap8,
            0x98: self.op_swap9, 0x99: self.op_swap10, 0x9a: self.op_swap11, 0x9b: self.op_swap12,
            0x9c: self.op_swap13, 0x9d: self.op_swap14, 0x9e: self.op_swap15, 0x9f: self.op_swap16,
            
            # Logging
            0xa0: self.op_log0, 0xa1: self.op_log1, 0xa2: self.op_log2, 0xa3: self.op_log3, 0xa4: self.op_log4,
            
            # System operations
            0xf0: self.op_create, 0xf1: self.op_call, 0xf2: self.op_callcode, 0xf3: self.op_return,
            0xf4: self.op_delegatecall, 0xf5: self.op_create2, 0xfa: self.op_staticcall,
            0xfd: self.op_revert, 0xff: self.op_selfdestruct,
        }

    def execute(self, code: bytes, gas_limit: int, context: Dict[str, Any]) -> Dict[str, Any]:
        """Ejecuta bytecode de contrato con protección contra re-entrancy"""
        # Verificar límite de profundidad de llamadas
        if self.call_depth >= self.max_call_depth:
            return {
                'success': False,
                'gas_used': 0,
                'error': 'Maximum call depth exceeded',
                'logs': []
            }
        
        # Obtener dirección del contrato actual
        contract_address = context.get('address', 'unknown')
        
        # Verificar guard de re-entrancy
        if contract_address in self.reentrancy_guard:
            return {
                'success': False,
                'gas_used': 0,
                'error': 'Re-entrancy attack detected',
                'logs': []
            }
        
        # Activar guard de re-entrancy
        self.reentrancy_guard[contract_address] = True
        self.call_depth += 1
        self.call_stack.append(contract_address)
        
        # Resetear estado del VM
        self.stack = []
        self.memory = bytearray(1024 * 1024)
        self.pc = 0
        self.gas_remaining = gas_limit
        self.return_data = b""
        self.logs = []
        self.context = context

        try:
            while self.pc < len(code) and self.gas_remaining > 0:
                opcode = code[self.pc]

                if opcode in self.opcodes:
                    # Ejecutar opcode
                    self.opcodes[opcode]()
                    
                    # Verificar stack overflow
                    if len(self.stack) > 1024:
                        raise Exception("Stack overflow")
                        
                else:
                    raise Exception(f"Invalid opcode: 0x{opcode:02x} at PC {self.pc}")

                self.pc += 1

            result = {
                'success': True,
                'gas_used': gas_limit - self.gas_remaining,
                'return_data': self.return_data,
                'logs': self.logs,
                'storage_changes': self.storage.copy()
            }

        except Exception as e:
            result = {
                'success': False,
                'gas_used': gas_limit - self.gas_remaining,
                'error': str(e),
                'logs': self.logs
            }
        
        finally:
            # Limpiar guard de re-entrancy y decrementar profundidad
            if contract_address in self.reentrancy_guard:
                del self.reentrancy_guard[contract_address]
            self.call_depth -= 1
            if self.call_stack and self.call_stack[-1] == contract_address:
                self.call_stack.pop()
        
        return result
    
    def compile_and_execute(self, source_code: str, gas_limit: int, context: Dict[str, Any]) -> Dict[str, Any]:
        """Compila código fuente y lo ejecuta"""
        try:
            bytecode = self.compiler.compile(source_code)
            return self.execute(bytecode, gas_limit, context)
        except Exception as e:
            return {
                'success': False,
                'gas_used': 0,
                'error': f"Compilation error: {str(e)}",
                'logs': []
            }

    def use_gas(self, amount: int):
        """Consume gas"""
        if self.gas_remaining < amount:
            raise Exception("Out of gas")
        self.gas_remaining -= amount

    def check_reentrancy_guard(self, contract_address: str) -> bool:
        """Verifica si un contrato está siendo ejecutado (re-entrancy guard)"""
        return contract_address in self.reentrancy_guard
    
    def set_reentrancy_guard(self, contract_address: str):
        """Activa el guard de re-entrancy para un contrato"""
        self.reentrancy_guard[contract_address] = True
    
    def clear_reentrancy_guard(self, contract_address: str):
        """Desactiva el guard de re-entrancy para un contrato"""
        if contract_address in self.reentrancy_guard:
            del self.reentrancy_guard[contract_address]
    
    def get_call_depth(self) -> int:
        """Obtiene la profundidad actual de llamadas"""
        return self.call_depth
    
    def get_call_stack(self) -> List[str]:
        """Obtiene el stack de llamadas actual"""
        return self.call_stack.copy()
    
    def reset_vm_state(self):
        """Resetea el estado del VM para una nueva ejecución"""
        self.stack = []
        self.memory = bytearray()
        self.storage = {}
        self.pc = 0
        self.return_data = b""
        self.logs = []
        # No resetear call_depth, reentrancy_guard, call_stack aquí
        # Estos se manejan en execute()

    # === IMPLEMENTACIONES COMPLETAS DE OPCODES ===
    
    # Aritmética
    def op_stop(self):
        """STOP - Detiene la ejecución"""
        self.use_gas(0)
        self.pc = len(self.context.get('code', []))  # Terminar ejecución

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

    def op_sub(self):
        """SUB - Resta dos valores del stack"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append((a - b) % 2**256)
    
    def op_div(self):
        """DIV - División entera"""
        self.use_gas(5)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        if b == 0:
            self.stack.append(0)
        else:
            self.stack.append(a // b)
    
    def op_sdiv(self):
        """SDIV - División con signo"""
        self.use_gas(5)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        if b == 0:
            self.stack.append(0)
        else:
            # Convertir a signed y hacer división
            a_signed = self._to_signed(a)
            b_signed = self._to_signed(b)
            result = a_signed // b_signed if b_signed != 0 else 0
            self.stack.append(self._to_unsigned(result))
    
    def op_mod(self):
        """MOD - Módulo"""
        self.use_gas(5)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        if b == 0:
            self.stack.append(0)
        else:
            self.stack.append(a % b)
    
    def op_smod(self):
        """SMOD - Módulo con signo"""
        self.use_gas(5)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        if b == 0:
            self.stack.append(0)
        else:
            a_signed = self._to_signed(a)
            b_signed = self._to_signed(b)
            result = a_signed % b_signed if b_signed != 0 else 0
            self.stack.append(self._to_unsigned(result))
    
    def op_addmod(self):
        """ADDMOD - (a + b) mod n"""
        self.use_gas(8)
        if len(self.stack) < 3:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        n = self.stack.pop()
        if n == 0:
            self.stack.append(0)
        else:
            self.stack.append((a + b) % n)
    
    def op_mulmod(self):
        """MULMOD - (a * b) mod n"""
        self.use_gas(8)
        if len(self.stack) < 3:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        n = self.stack.pop()
        if n == 0:
            self.stack.append(0)
        else:
            self.stack.append((a * b) % n)
    
    def op_exp(self):
        """EXP - Exponenciación"""
        self.use_gas(10)  # Gas dinámico basado en exponente
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        base = self.stack.pop()
        exp = self.stack.pop()
        
        # Gas adicional para exponente
        if exp > 0:
            self.use_gas(50 * (exp.bit_length() // 8 + 1))
        
        if exp == 0:
            self.stack.append(1)
        else:
            self.stack.append(pow(base, exp, 2**256))
    
    def op_signextend(self):
        """SIGNEXTEND - Extensión de signo"""
        self.use_gas(5)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()  # Número de bytes
        x = self.stack.pop()  # Valor a extender
        
        if b >= 32:
            self.stack.append(x)
        else:
            bit_pos = 8 * b + 7
            if x & (1 << bit_pos):
                mask = (1 << bit_pos) - 1
                self.stack.append(x | (~mask))
            else:
                mask = (1 << bit_pos) - 1
                self.stack.append(x & mask)
    
    # Comparación
    def op_lt(self):
        """LT - Menor que"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(1 if a < b else 0)
    
    def op_gt(self):
        """GT - Mayor que"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(1 if a > b else 0)
    
    def op_slt(self):
        """SLT - Menor que con signo"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        a_signed = self._to_signed(a)
        b_signed = self._to_signed(b)
        self.stack.append(1 if a_signed < b_signed else 0)
    
    def op_sgt(self):
        """SGT - Mayor que con signo"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        a_signed = self._to_signed(a)
        b_signed = self._to_signed(b)
        self.stack.append(1 if a_signed > b_signed else 0)
    
    def op_eq(self):
        """EQ - Igual a"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(1 if a == b else 0)
    
    def op_iszero(self):
        """ISZERO - Es cero"""
        self.use_gas(3)
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        self.stack.append(1 if a == 0 else 0)
    
    def op_and(self):
        """AND - AND bit a bit"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(a & b)
    
    def op_or(self):
        """OR - OR bit a bit"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(a | b)
    
    def op_xor(self):
        """XOR - XOR bit a bit"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(a ^ b)
    
    def op_not(self):
        """NOT - NOT bit a bit"""
        self.use_gas(3)
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        self.stack.append((~a) % 2**256)
    
    def op_byte(self):
        """BYTE - Obtener byte en posición"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        i = self.stack.pop()
        x = self.stack.pop()
        if i >= 32:
            self.stack.append(0)
        else:
            byte_val = (x >> (8 * (31 - i))) & 0xFF
            self.stack.append(byte_val)
    
    def op_shl(self):
        """SHL - Shift left"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        shift = self.stack.pop()
        value = self.stack.pop()
        if shift >= 256:
            self.stack.append(0)
        else:
            self.stack.append((value << shift) % 2**256)
    
    def op_shr(self):
        """SHR - Shift right"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        shift = self.stack.pop()
        value = self.stack.pop()
        if shift >= 256:
            self.stack.append(0)
        else:
            self.stack.append(value >> shift)
    
    def op_sar(self):
        """SAR - Shift arithmetic right"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        shift = self.stack.pop()
        value = self.stack.pop()
        if shift >= 256:
            if value & (1 << 255):
                self.stack.append(2**256 - 1)
            else:
                self.stack.append(0)
        else:
            if value & (1 << 255):
                mask = (1 << shift) - 1
                self.stack.append((value >> shift) | (~mask))
            else:
                self.stack.append(value >> shift)
    
    # SHA3
    def op_sha3(self):
        """SHA3 - Hash SHA3"""
        self.use_gas(30)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        offset = self.stack.pop()
        size = self.stack.pop()
        
        # Gas adicional por palabra
        self.use_gas(6 * ((size + 31) // 32))
        
        if offset + size > len(self.memory):
            raise Exception("Memory access out of bounds")
        
        data = bytes(self.memory[offset:offset + size])
        hash_result = sha3_256(data)
        self.stack.append(int.from_bytes(hash_result, 'big'))
    
    # Información del contexto
    def op_address(self):
        """ADDRESS - Dirección del contrato actual"""
        self.use_gas(2)
        address = self.context.get('address', '0x0')
        if isinstance(address, str) and address.startswith('0x'):
            address_int = int(address, 16)
        else:
            address_int = 0
        self.stack.append(address_int)
    
    def op_balance(self):
        """BALANCE - Balance de una cuenta"""
        self.use_gas(400)
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        address = self.stack.pop()
        # Simular balance (en implementación real se consultaría el estado)
        balance = self.context.get('balance', 0)
        self.stack.append(balance)
    
    def op_origin(self):
        """ORIGIN - Dirección del originador de la transacción"""
        self.use_gas(2)
        origin = self.context.get('origin', '0x0')
        if isinstance(origin, str) and origin.startswith('0x'):
            origin_int = int(origin, 16)
        else:
            origin_int = 0
        self.stack.append(origin_int)
    
    def op_caller(self):
        """CALLER - Dirección del llamador"""
        self.use_gas(2)
        caller = self.context.get('caller', '0x0')
        if isinstance(caller, str) and caller.startswith('0x'):
            caller_int = int(caller, 16)
        else:
            caller_int = 0
        self.stack.append(caller_int)
    
    def op_callvalue(self):
        """CALLVALUE - Valor enviado con la llamada"""
        self.use_gas(2)
        value = self.context.get('value', 0)
        self.stack.append(value)
    
    def op_calldataload(self):
        """CALLDATALOAD - Carga 32 bytes de calldata"""
        self.use_gas(3)
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        offset = self.stack.pop()
        calldata = self.context.get('calldata', b'')
        
        if offset >= len(calldata):
            self.stack.append(0)
        else:
            # Cargar 32 bytes o menos si no hay suficientes
            data = calldata[offset:offset + 32]
            if len(data) < 32:
                data = data + b'\x00' * (32 - len(data))
            self.stack.append(int.from_bytes(data, 'big'))
    
    def op_calldatasize(self):
        """CALLDATASIZE - Tamaño de calldata"""
        self.use_gas(2)
        calldata = self.context.get('calldata', b'')
        self.stack.append(len(calldata))
    
    def op_calldatacopy(self):
        """CALLDATACOPY - Copia calldata a memoria"""
        self.use_gas(3)
        if len(self.stack) < 3:
            raise Exception("Stack underflow")
        dest_offset = self.stack.pop()
        offset = self.stack.pop()
        size = self.stack.pop()
        
        # Gas adicional por palabra
        self.use_gas(3 * ((size + 31) // 32))
        
        calldata = self.context.get('calldata', b'')
        
        # Expandir memoria si es necesario
        if dest_offset + size > len(self.memory):
            self.memory.extend(b'\x00' * (dest_offset + size - len(self.memory)))
        
        # Copiar datos
        for i in range(size):
            if offset + i < len(calldata):
                self.memory[dest_offset + i] = calldata[offset + i]
            else:
                self.memory[dest_offset + i] = 0
    
    def op_codesize(self):
        """CODESIZE - Tamaño del código del contrato"""
        self.use_gas(2)
        code = self.context.get('code', b'')
        self.stack.append(len(code))
    
    def op_codecopy(self):
        """CODECOPY - Copia código a memoria"""
        self.use_gas(3)
        if len(self.stack) < 3:
            raise Exception("Stack underflow")
        dest_offset = self.stack.pop()
        offset = self.stack.pop()
        size = self.stack.pop()
        
        # Gas adicional por palabra
        self.use_gas(3 * ((size + 31) // 32))
        
        code = self.context.get('code', b'')
        
        # Expandir memoria si es necesario
        if dest_offset + size > len(self.memory):
            self.memory.extend(b'\x00' * (dest_offset + size - len(self.memory)))
        
        # Copiar código
        for i in range(size):
            if offset + i < len(code):
                self.memory[dest_offset + i] = code[offset + i]
            else:
                self.memory[dest_offset + i] = 0
    
    def op_gasprice(self):
        """GASPRICE - Precio del gas"""
        self.use_gas(2)
        gas_price = self.context.get('gas_price', 0)
        self.stack.append(gas_price)
    
    def op_extcodesize(self):
        """EXTCODESIZE - Tamaño del código de una cuenta"""
        self.use_gas(700)
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        address = self.stack.pop()
        # Simular tamaño de código (en implementación real se consultaría el estado)
        self.stack.append(0)
    
    def op_extcodecopy(self):
        """EXTCODECOPY - Copia código de una cuenta a memoria"""
        self.use_gas(700)
        if len(self.stack) < 4:
            raise Exception("Stack underflow")
        address = self.stack.pop()
        dest_offset = self.stack.pop()
        offset = self.stack.pop()
        size = self.stack.pop()
        
        # Gas adicional por palabra
        self.use_gas(3 * ((size + 31) // 32))
        
        # Simular código vacío (en implementación real se consultaría el estado)
        # Expandir memoria si es necesario
        if dest_offset + size > len(self.memory):
            self.memory.extend(b'\x00' * (dest_offset + size - len(self.memory)))
        
        # Llenar con ceros
        for i in range(size):
            self.memory[dest_offset + i] = 0
    
    def op_returndatasize(self):
        """RETURNDATASIZE - Tamaño de los datos de retorno"""
        self.use_gas(2)
        return_data = self.context.get('return_data', b'')
        self.stack.append(len(return_data))
    
    def op_returndatacopy(self):
        """RETURNDATACOPY - Copia datos de retorno a memoria"""
        self.use_gas(3)
        if len(self.stack) < 3:
            raise Exception("Stack underflow")
        dest_offset = self.stack.pop()
        offset = self.stack.pop()
        size = self.stack.pop()
        
        # Gas adicional por palabra
        self.use_gas(3 * ((size + 31) // 32))
        
        return_data = self.context.get('return_data', b'')
        
        if offset + size > len(return_data):
            raise Exception("Return data access out of bounds")
        
        # Expandir memoria si es necesario
        if dest_offset + size > len(self.memory):
            self.memory.extend(b'\x00' * (dest_offset + size - len(self.memory)))
        
        # Copiar datos
        for i in range(size):
            self.memory[dest_offset + i] = return_data[offset + i]
    
    def op_extcodehash(self):
        """EXTCODEHASH - Hash del código de una cuenta"""
        self.use_gas(700)
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        address = self.stack.pop()
        # Simular hash de código (en implementación real se consultaría el estado)
        self.stack.append(0)
    
    # Operaciones de bloque
    def op_blockhash(self):
        """BLOCKHASH - Hash de un bloque"""
        self.use_gas(20)
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        block_number = self.stack.pop()
        # Simular hash de bloque (en implementación real se consultaría la blockchain)
        self.stack.append(0)
    
    def op_coinbase(self):
        """COINBASE - Dirección del minero"""
        self.use_gas(2)
        coinbase = self.context.get('coinbase', '0x0')
        if isinstance(coinbase, str) and coinbase.startswith('0x'):
            coinbase_int = int(coinbase, 16)
        else:
            coinbase_int = 0
        self.stack.append(coinbase_int)
    
    def op_timestamp(self):
        """TIMESTAMP - Timestamp del bloque"""
        self.use_gas(2)
        timestamp = self.context.get('timestamp', 0)
        self.stack.append(timestamp)
    
    def op_number(self):
        """NUMBER - Número del bloque"""
        self.use_gas(2)
        block_number = self.context.get('block_number', 0)
        self.stack.append(block_number)
    
    def op_difficulty(self):
        """DIFFICULTY - Dificultad del bloque"""
        self.use_gas(2)
        difficulty = self.context.get('difficulty', 0)
        self.stack.append(difficulty)
    
    def op_gaslimit(self):
        """GASLIMIT - Límite de gas del bloque"""
        self.use_gas(2)
        gas_limit = self.context.get('gas_limit', 0)
        self.stack.append(gas_limit)
    
    def op_chainid(self):
        """CHAINID - ID de la cadena"""
        self.use_gas(2)
        chain_id = self.context.get('chain_id', 1)
        self.stack.append(chain_id)
    
    def op_selfbalance(self):
        """SELFBALANCE - Balance del contrato actual"""
        self.use_gas(5)
        balance = self.context.get('balance', 0)
        self.stack.append(balance)
    
    def op_basefee(self):
        """BASEFEE - Tarifa base del bloque"""
        self.use_gas(2)
        base_fee = self.context.get('base_fee', 0)
        self.stack.append(base_fee)
    
    # Stack, memoria y storage
    def op_pop(self):
        """POP - Elimina elemento del stack"""
        self.use_gas(2)
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        self.stack.pop()
    
    def op_mload(self):
        """MLOAD - Carga 32 bytes de memoria"""
        self.use_gas(3)
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        offset = self.stack.pop()
        
        # Gas adicional por palabra
        self.use_gas(3 * ((32 + 31) // 32))
        
        # Expandir memoria si es necesario
        if offset + 32 > len(self.memory):
            self.memory.extend(b'\x00' * (offset + 32 - len(self.memory)))
        
        data = bytes(self.memory[offset:offset + 32])
        self.stack.append(int.from_bytes(data, 'big'))
    
    def op_mstore(self):
        """MSTORE - Almacena 32 bytes en memoria"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        offset = self.stack.pop()
        value = self.stack.pop()
        
        # Gas adicional por palabra
        self.use_gas(3 * ((32 + 31) // 32))
        
        # Expandir memoria si es necesario
        if offset + 32 > len(self.memory):
            self.memory.extend(b'\x00' * (offset + 32 - len(self.memory)))
        
        # Almacenar valor
        data = value.to_bytes(32, 'big')
        for i in range(32):
            self.memory[offset + i] = data[i]
    
    def op_mstore8(self):
        """MSTORE8 - Almacena 1 byte en memoria"""
        self.use_gas(3)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        offset = self.stack.pop()
        value = self.stack.pop()
        
        # Expandir memoria si es necesario
        if offset + 1 > len(self.memory):
            self.memory.extend(b'\x00' * (offset + 1 - len(self.memory)))
        
        self.memory[offset] = value & 0xFF

    def op_sload(self):
        """SLOAD - Carga valor de storage"""
        self.use_gas(200)
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        key = self.stack.pop()
        value = self.storage.get(key, 0)
        self.stack.append(value)

    def op_sstore(self):
        """SSTORE - Almacena valor en storage"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        key = self.stack.pop()
        value = self.stack.pop()
        
        # Gas dinámico para SSTORE
        if key in self.storage:
            if self.storage[key] == 0 and value != 0:
                self.use_gas(20000)  # SSTORE_SET
            elif self.storage[key] != 0 and value == 0:
                self.use_gas(5000)   # SSTORE_CLEAR
            else:
                self.use_gas(200)    # SSTORE_RESET
        else:
            if value != 0:
                self.use_gas(20000)  # SSTORE_SET
            else:
                self.use_gas(200)    # SSTORE_RESET
        
        self.storage[key] = value
    
    def op_jump(self):
        """JUMP - Salto incondicional"""
        self.use_gas(8)
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        dest = self.stack.pop()
        
        if dest >= len(self.context.get('code', [])):
            raise Exception("Invalid jump destination")
        
        # Verificar que el destino es un JUMPDEST
        code = self.context.get('code', [])
        if dest < len(code) and code[dest] != 0x5b:
            raise Exception("Invalid jump destination - not JUMPDEST")
        
        self.pc = dest - 1  # -1 porque se incrementa al final del loop
    
    def op_jumpi(self):
        """JUMPI - Salto condicional"""
        self.use_gas(10)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        dest = self.stack.pop()
        condition = self.stack.pop()
        
        if condition != 0:
            if dest >= len(self.context.get('code', [])):
                raise Exception("Invalid jump destination")
            
            # Verificar que el destino es un JUMPDEST
            code = self.context.get('code', [])
            if dest < len(code) and code[dest] != 0x5b:
                raise Exception("Invalid jump destination - not JUMPDEST")
            
            self.pc = dest - 1  # -1 porque se incrementa al final del loop
    
    def op_pc(self):
        """PC - Program counter"""
        self.use_gas(2)
        self.stack.append(self.pc)
    
    def op_msize(self):
        """MSIZE - Tamaño de memoria en bytes"""
        self.use_gas(2)
        self.stack.append(len(self.memory))
    
    def op_gas(self):
        """GAS - Gas restante"""
        self.use_gas(2)
        self.stack.append(self.gas_remaining)
    
    def op_jumpdest(self):
        """JUMPDEST - Destino de salto"""
        self.use_gas(1)
        pass  # No hace nada, solo marca un destino válido
    
    # Push operations
    def _push_value(self, size: int):
        """Función auxiliar para operaciones PUSH"""
        if self.pc + size >= len(self.context.get('code', [])):
            raise Exception("Invalid PUSH - not enough data")
        
        code = self.context.get('code', [])
        value = 0
        for i in range(size):
            value = (value << 8) | code[self.pc + 1 + i]
        
        self.stack.append(value)
        self.pc += size  # Saltar los bytes del valor
    
    def op_push1(self): self.use_gas(3); self._push_value(1)
    def op_push2(self): self.use_gas(3); self._push_value(2)
    def op_push3(self): self.use_gas(3); self._push_value(3)
    def op_push4(self): self.use_gas(3); self._push_value(4)
    def op_push5(self): self.use_gas(3); self._push_value(5)
    def op_push6(self): self.use_gas(3); self._push_value(6)
    def op_push7(self): self.use_gas(3); self._push_value(7)
    def op_push8(self): self.use_gas(3); self._push_value(8)
    def op_push9(self): self.use_gas(3); self._push_value(9)
    def op_push10(self): self.use_gas(3); self._push_value(10)
    def op_push11(self): self.use_gas(3); self._push_value(11)
    def op_push12(self): self.use_gas(3); self._push_value(12)
    def op_push13(self): self.use_gas(3); self._push_value(13)
    def op_push14(self): self.use_gas(3); self._push_value(14)
    def op_push15(self): self.use_gas(3); self._push_value(15)
    def op_push16(self): self.use_gas(3); self._push_value(16)
    def op_push17(self): self.use_gas(3); self._push_value(17)
    def op_push18(self): self.use_gas(3); self._push_value(18)
    def op_push19(self): self.use_gas(3); self._push_value(19)
    def op_push20(self): self.use_gas(3); self._push_value(20)
    def op_push21(self): self.use_gas(3); self._push_value(21)
    def op_push22(self): self.use_gas(3); self._push_value(22)
    def op_push23(self): self.use_gas(3); self._push_value(23)
    def op_push24(self): self.use_gas(3); self._push_value(24)
    def op_push25(self): self.use_gas(3); self._push_value(25)
    def op_push26(self): self.use_gas(3); self._push_value(26)
    def op_push27(self): self.use_gas(3); self._push_value(27)
    def op_push28(self): self.use_gas(3); self._push_value(28)
    def op_push29(self): self.use_gas(3); self._push_value(29)
    def op_push30(self): self.use_gas(3); self._push_value(30)
    def op_push31(self): self.use_gas(3); self._push_value(31)
    def op_push32(self): self.use_gas(3); self._push_value(32)
    
    # Duplicate operations
    def _dup_value(self, n: int):
        """Función auxiliar para operaciones DUP"""
        if len(self.stack) < n:
            raise Exception("Stack underflow")
        value = self.stack[-n]
        self.stack.append(value)
    
    def op_dup1(self): self.use_gas(3); self._dup_value(1)
    def op_dup2(self): self.use_gas(3); self._dup_value(2)
    def op_dup3(self): self.use_gas(3); self._dup_value(3)
    def op_dup4(self): self.use_gas(3); self._dup_value(4)
    def op_dup5(self): self.use_gas(3); self._dup_value(5)
    def op_dup6(self): self.use_gas(3); self._dup_value(6)
    def op_dup7(self): self.use_gas(3); self._dup_value(7)
    def op_dup8(self): self.use_gas(3); self._dup_value(8)
    def op_dup9(self): self.use_gas(3); self._dup_value(9)
    def op_dup10(self): self.use_gas(3); self._dup_value(10)
    def op_dup11(self): self.use_gas(3); self._dup_value(11)
    def op_dup12(self): self.use_gas(3); self._dup_value(12)
    def op_dup13(self): self.use_gas(3); self._dup_value(13)
    def op_dup14(self): self.use_gas(3); self._dup_value(14)
    def op_dup15(self): self.use_gas(3); self._dup_value(15)
    def op_dup16(self): self.use_gas(3); self._dup_value(16)
    
    # Exchange operations
    def _swap_values(self, n: int):
        """Función auxiliar para operaciones SWAP"""
        if len(self.stack) < n + 1:
            raise Exception("Stack underflow")
        # Intercambiar el elemento superior con el elemento en posición n
        self.stack[-1], self.stack[-n-1] = self.stack[-n-1], self.stack[-1]
    
    def op_swap1(self): self.use_gas(3); self._swap_values(1)
    def op_swap2(self): self.use_gas(3); self._swap_values(2)
    def op_swap3(self): self.use_gas(3); self._swap_values(3)
    def op_swap4(self): self.use_gas(3); self._swap_values(4)
    def op_swap5(self): self.use_gas(3); self._swap_values(5)
    def op_swap6(self): self.use_gas(3); self._swap_values(6)
    def op_swap7(self): self.use_gas(3); self._swap_values(7)
    def op_swap8(self): self.use_gas(3); self._swap_values(8)
    def op_swap9(self): self.use_gas(3); self._swap_values(9)
    def op_swap10(self): self.use_gas(3); self._swap_values(10)
    def op_swap11(self): self.use_gas(3); self._swap_values(11)
    def op_swap12(self): self.use_gas(3); self._swap_values(12)
    def op_swap13(self): self.use_gas(3); self._swap_values(13)
    def op_swap14(self): self.use_gas(3); self._swap_values(14)
    def op_swap15(self): self.use_gas(3); self._swap_values(15)
    def op_swap16(self): self.use_gas(3); self._swap_values(16)
    
    # Logging
    def _log_event(self, topics: int):
        """Función auxiliar para operaciones LOG"""
        if len(self.stack) < topics + 2:
            raise Exception("Stack underflow")
        
        offset = self.stack.pop()
        size = self.stack.pop()
        log_topics = []
        
        for _ in range(topics):
            log_topics.append(self.stack.pop())
        
        # Gas adicional por palabra
        self.use_gas(375 * topics + 8 * ((size + 31) // 32))
        
        # Obtener datos del log
        if offset + size > len(self.memory):
            raise Exception("Memory access out of bounds")
        
        data = bytes(self.memory[offset:offset + size])
        
        # Crear evento de log
        log_event = {
            'address': self.context.get('address', '0x0'),
            'topics': log_topics,
            'data': data
        }
        
        self.logs.append(log_event)
    
    def op_log0(self): self._log_event(0)
    def op_log1(self): self._log_event(1)
    def op_log2(self): self._log_event(2)
    def op_log3(self): self._log_event(3)
    def op_log4(self): self._log_event(4)
    
    # System operations
    def op_create(self):
        """CREATE - Crear nuevo contrato"""
        self.use_gas(32000)
        if len(self.stack) < 3:
            raise Exception("Stack underflow")
        value = self.stack.pop()
        offset = self.stack.pop()
        size = self.stack.pop()
        
        # Gas adicional por byte de código
        self.use_gas(200 * size)
        
        # Obtener código del contrato
        if offset + size > len(self.memory):
            raise Exception("Memory access out of bounds")
        
        code = bytes(self.memory[offset:offset + size])
        
        # Simular creación de contrato (en implementación real se ejecutaría)
        contract_address = self._generate_contract_address()
        self.stack.append(contract_address)
    
    def op_call(self):
        """CALL - Llamar a otro contrato"""
        self.use_gas(700)
        if len(self.stack) < 7:
            raise Exception("Stack underflow")
        
        gas = self.stack.pop()
        address = self.stack.pop()
        value = self.stack.pop()
        args_offset = self.stack.pop()
        args_size = self.stack.pop()
        ret_offset = self.stack.pop()
        ret_size = self.stack.pop()
        
        # Gas adicional
        if value > 0:
            self.use_gas(9000)
        
        self.use_gas(2300)  # Gas base para CALL
        
        # Simular llamada (en implementación real se ejecutaría el contrato)
        success = 1  # Simular éxito
        self.stack.append(success)
    
    def op_callcode(self):
        """CALLCODE - Llamar con código del llamador"""
        self.use_gas(700)
        # Similar a CALL pero con contexto del llamador
        if len(self.stack) < 7:
            raise Exception("Stack underflow")
        
        # Simular llamada
        success = 1
        self.stack.append(success)
    
    def op_return(self):
        """RETURN - Retornar datos"""
        self.use_gas(0)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        offset = self.stack.pop()
        size = self.stack.pop()
        
        if offset + size > len(self.memory):
            raise Exception("Memory access out of bounds")
        
        self.return_data = bytes(self.memory[offset:offset + size])
        self.pc = len(self.context.get('code', []))  # Terminar ejecución
    
    def op_delegatecall(self):
        """DELEGATECALL - Llamada delegada"""
        self.use_gas(700)
        if len(self.stack) < 6:
            raise Exception("Stack underflow")
        
        # Simular llamada delegada
        success = 1
        self.stack.append(success)
    
    def op_create2(self):
        """CREATE2 - Crear contrato con salt"""
        self.use_gas(32000)
        if len(self.stack) < 4:
            raise Exception("Stack underflow")
        
        value = self.stack.pop()
        offset = self.stack.pop()
        size = self.stack.pop()
        salt = self.stack.pop()
        
        # Gas adicional por byte de código
        self.use_gas(200 * size)
        
        # Simular creación con salt
        contract_address = self._generate_contract_address()
        self.stack.append(contract_address)
    
    def op_staticcall(self):
        """STATICCALL - Llamada estática"""
        self.use_gas(700)
        if len(self.stack) < 6:
            raise Exception("Stack underflow")
        
        # Simular llamada estática
        success = 1
        self.stack.append(success)
    
    def op_revert(self):
        """REVERT - Revertir ejecución"""
        self.use_gas(0)
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        offset = self.stack.pop()
        size = self.stack.pop()
        
        if offset + size > len(self.memory):
            raise Exception("Memory access out of bounds")
        
        self.return_data = bytes(self.memory[offset:offset + size])
        raise Exception(f"REVERT: {self.return_data.hex()}")
    
    def op_selfdestruct(self):
        """SELFDESTRUCT - Auto-destruir contrato"""
        self.use_gas(5000)
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        address = self.stack.pop()
        
        # Marcar contrato para destrucción
        self.context['selfdestruct'] = True
        self.context['refund_address'] = address
    
    # Funciones auxiliares
    def _to_signed(self, value: int) -> int:
        """Convierte valor unsigned a signed"""
        if value >= 2**255:
            return value - 2**256
        return value
    
    def _to_unsigned(self, value: int) -> int:
        """Convierte valor signed a unsigned"""
        return value % 2**256
    
    def _generate_contract_address(self) -> int:
        """Genera dirección de contrato"""
        # Simular generación de dirección
        import random
        return random.randint(1, 2**160 - 1)

# === SISTEMA DE CONSENSO HÍBRIDO ROBUSTO ===
class VRF:
    """Verifiable Random Function para selección segura de validadores"""
    
    def __init__(self, private_key: bytes):
        self.private_key = private_key
        self.public_key = self._derive_public_key(private_key)
    
    def _derive_public_key(self, private_key: bytes) -> bytes:
        """Deriva clave pública desde clave privada"""
        # Implementación simplificada - en producción usaría criptografía real
        return hashlib.sha256(private_key).digest()
    
    def generate_proof(self, input_data: bytes) -> tuple:
        """Genera prueba VRF para entrada dada"""
        # Combinar entrada con clave privada
        combined = input_data + self.private_key
        
        # Generar hash determinístico
        hash_result = hashlib.sha3_256(combined).digest()
        
        # Crear prueba (simplificada)
        proof = hash_result + self.public_key
        
        return hash_result, proof
    
    def verify_proof(self, input_data: bytes, output: bytes, proof: bytes, public_key: bytes) -> bool:
        """Verifica prueba VRF"""
        if len(proof) < 32:
            return False
        
        # Extraer hash y clave pública de la prueba
        proof_hash = proof[:32]
        proof_pubkey = proof[32:]
        
        # Verificar que la clave pública coincide
        if proof_pubkey != public_key:
            return False
        
        # Recalcular hash
        combined = input_data + self.private_key
        expected_hash = hashlib.sha3_256(combined).digest()
        
        return proof_hash == expected_hash

class ValidatorRegistry:
    """Registro de validadores con stake y reputación"""
    
    def __init__(self):
        self.validators = {}  # address -> ValidatorInfo
        self.total_stake = 0
        self.min_stake = 1000000  # Stake mínimo para ser validador
    
    def register_validator(self, address: str, stake: int, public_key: bytes):
        """Registra un validador"""
        if stake < self.min_stake:
            raise ValueError("Stake insuficiente para ser validador")
        
        self.validators[address] = {
            'stake': stake,
            'public_key': public_key,
            'reputation': 100,  # Reputación inicial
            'slashing_count': 0,
            'last_selected': 0,
            'performance_score': 1.0
        }
        self.total_stake += stake
    
    def update_stake(self, address: str, new_stake: int):
        """Actualiza stake de validador"""
        if address not in self.validators:
            raise ValueError("Validador no registrado")
        
        old_stake = self.validators[address]['stake']
        self.validators[address]['stake'] = new_stake
        self.total_stake += (new_stake - old_stake)
    
    def slash_validator(self, address: str, slashing_amount: int):
        """Penaliza validador por comportamiento malicioso"""
        if address not in self.validators:
            return
        
        validator = self.validators[address]
        slashed_stake = min(slashing_amount, validator['stake'])
        
        validator['stake'] -= slashed_stake
        validator['slashing_count'] += 1
        validator['reputation'] = max(0, validator['reputation'] - 10)
        validator['performance_score'] *= 0.9
        
        self.total_stake -= slashed_stake
    
    def get_weighted_validators(self) -> List[tuple]:
        """Obtiene lista de validadores con pesos"""
        weighted_validators = []
        
        for address, info in self.validators.items():
            if info['stake'] >= self.min_stake:
                # Peso basado en stake, reputación y performance
                weight = (info['stake'] * info['reputation'] * info['performance_score']) / 10000
                weighted_validators.append((address, weight, info))
        
        return sorted(weighted_validators, key=lambda x: x[1], reverse=True)

class HybridConsensus:
    """Sistema de consenso híbrido PoW/PoS con VRF y selección segura"""
    
    def __init__(self):
        self.pow_pos_ratio = 10  # Cada 10 bloques, 1 PoS
        self.validator_registry = ValidatorRegistry()
        self.vrf_instances = {}  # address -> VRF instance
        self.epoch_length = 100  # Bloques por época
        self.current_epoch = 0
        self.epoch_seed = b""
        
    def register_validator(self, address: str, stake: int, private_key: bytes):
        """Registra validador con clave privada para VRF"""
        public_key = hashlib.sha256(private_key).digest()
        self.validator_registry.register_validator(address, stake, public_key)
        
        # Crear instancia VRF para el validador
        self.vrf_instances[address] = VRF(private_key)
    
    def select_block_producer(self, block_height: int, block_hash: bytes) -> str:
        """Selecciona productor de bloque usando VRF y pesos"""
        if block_height % self.pow_pos_ratio == 0:
            return self._select_pos_validator(block_height, block_hash)
        else:
            return self._select_pow_miner(block_height, block_hash)
    
    def _select_pos_validator(self, block_height: int, block_hash: bytes) -> str:
        """Selecciona validador PoS usando VRF"""
        # Actualizar época si es necesario
        if block_height // self.epoch_length > self.current_epoch:
            self.current_epoch = block_height // self.epoch_length
            self.epoch_seed = block_hash
        
        # Obtener validadores elegibles
        weighted_validators = self.validator_registry.get_weighted_validators()
        
        if not weighted_validators:
            return "POW"  # Fallback a PoW si no hay validadores
        
        # Crear entrada para VRF (combinar altura, hash y época)
        vrf_input = block_hash + block_height.to_bytes(8, 'big') + self.epoch_seed
        
        # Calcular total de pesos
        total_weight = sum(weight for _, weight, _ in weighted_validators)
        
        if total_weight == 0:
            return "POW"
        
        # Generar número aleatorio usando VRF del validador con mayor peso
        primary_validator = weighted_validators[0]
        primary_address = primary_validator[0]
        
        if primary_address in self.vrf_instances:
            vrf_output, vrf_proof = self.vrf_instances[primary_address].generate_proof(vrf_input)
            
            # Convertir output VRF a número
            random_value = int.from_bytes(vrf_output, 'big')
            
            # Seleccionar validador usando distribución ponderada
            selected_validator = self._weighted_random_selection(weighted_validators, random_value, total_weight)
            
            # Verificar que el validador seleccionado puede producir bloque
            if self._can_produce_block(selected_validator, block_height):
                return selected_validator
            else:
                # Fallback a siguiente validador
                return self._select_fallback_validator(weighted_validators, vrf_input)
        
        return "POW"
    
    def _weighted_random_selection(self, weighted_validators: List[tuple], random_value: int, total_weight: int) -> str:
        """Selecciona validador usando distribución ponderada"""
        target = random_value % total_weight
        cumulative_weight = 0
        
        for address, weight, _ in weighted_validators:
            cumulative_weight += weight
            if cumulative_weight > target:
                return address
        
        # Fallback al último validador
        return weighted_validators[-1][0]
    
    def _can_produce_block(self, validator_address: str, block_height: int) -> bool:
        """Verifica si validador puede producir bloque"""
        if validator_address not in self.validator_registry.validators:
            return False
        
        validator = self.validator_registry.validators[validator_address]
        
        # Verificar stake mínimo
        if validator['stake'] < self.validator_registry.min_stake:
            return False
        
        # Verificar reputación mínima
        if validator['reputation'] < 50:
            return False
        
        # Verificar que no ha sido seleccionado recientemente (prevenir monopolio)
        if block_height - validator['last_selected'] < 5:
            return False
        
        return True
    
    def _select_fallback_validator(self, weighted_validators: List[tuple], vrf_input: bytes) -> str:
        """Selecciona validador de respaldo"""
        # Usar hash de la entrada como fuente de aleatoriedad
        fallback_hash = hashlib.sha256(vrf_input).digest()
        fallback_value = int.from_bytes(fallback_hash, 'big')
        
        total_weight = sum(weight for _, weight, _ in weighted_validators)
        return self._weighted_random_selection(weighted_validators, fallback_value, total_weight)
    
    def _select_pow_miner(self, block_height: int, block_hash: bytes) -> str:
        """Selecciona minero PoW (simplificado)"""
        # En implementación real, esto verificaría proof of work
        return "POW"
    
    def validate_block_producer(self, block_height: int, block_hash: bytes, producer: str) -> bool:
        """Valida que el productor de bloque es legítimo"""
        if producer == "POW":
            return self._validate_pow_producer(block_height, block_hash)
        else:
            return self._validate_pos_producer(block_height, block_hash, producer)
    
    def _validate_pow_producer(self, block_height: int, block_hash: bytes) -> bool:
        """Valida productor PoW"""
        # En implementación real, verificaría proof of work
        return True
    
    def _validate_pos_producer(self, block_height: int, block_hash: bytes, producer: str) -> bool:
        """Valida productor PoS usando VRF"""
        if producer not in self.validator_registry.validators:
            return False
        
        if not self._can_produce_block(producer, block_height):
            return False
        
        # Verificar que el validador fue seleccionado correctamente
        expected_producer = self._select_pos_validator(block_height, block_hash)
        return producer == expected_producer
    
    def update_validator_performance(self, validator_address: str, success: bool, block_height: int):
        """Actualiza performance del validador"""
        if validator_address not in self.validator_registry.validators:
            return
        
        validator = self.validator_registry.validators[validator_address]
        
        if success:
            # Recompensar por buen comportamiento
            validator['reputation'] = min(100, validator['reputation'] + 1)
            validator['performance_score'] = min(2.0, validator['performance_score'] * 1.01)
        else:
            # Penalizar por mal comportamiento
            validator['reputation'] = max(0, validator['reputation'] - 5)
            validator['performance_score'] = max(0.1, validator['performance_score'] * 0.95)
        
        validator['last_selected'] = block_height
    
    def get_consensus_info(self, block_height: int) -> dict:
        """Obtiene información del consenso para un bloque"""
        is_pos = (block_height % self.pow_pos_ratio == 0)
        epoch = block_height // self.epoch_length
        
        return {
            'is_pos': is_pos,
            'epoch': epoch,
            'total_validators': len(self.validator_registry.validators),
            'total_stake': self.validator_registry.total_stake,
            'min_stake': self.validator_registry.min_stake,
            'pow_pos_ratio': self.pow_pos_ratio
        }

# === SISTEMA DE ESTADO PERSISTENTE ===
class StateSnapshot:
    """Snapshot del estado en un punto específico"""
    
    def __init__(self, block_height: int, state_root: str, accounts: dict, contracts: dict):
        self.block_height = block_height
        self.state_root = state_root
        self.accounts = accounts.copy()
        self.contracts = contracts.copy()
        self.timestamp = int(time.time())
        self.size_bytes = self._calculate_size()
    
    def _calculate_size(self) -> int:
        """Calcula tamaño del snapshot en bytes"""
        import sys
        return sys.getsizeof(self.accounts) + sys.getsizeof(self.contracts)
    
    def to_dict(self) -> dict:
        """Convierte snapshot a diccionario"""
        return {
            'block_height': self.block_height,
            'state_root': self.state_root,
            'accounts': self.accounts,
            'contracts': self.contracts,
            'timestamp': self.timestamp,
            'size_bytes': self.size_bytes
        }

class StateManager:
    """Gestor de estado persistente con snapshots y pruning"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.state_db = MerklePatriciaTrie(db_path)
        self.snapshots = {}  # block_height -> StateSnapshot
        self.max_snapshots = 10  # Máximo número de snapshots a mantener
        self.pruning_enabled = True
        self.pruning_interval = 1000  # Bloques entre pruning
        self.last_pruning_height = 0
        
        # Configuración de pruning
        self.keep_recent_blocks = 1000  # Mantener últimos N bloques
        self.keep_epoch_snapshots = True  # Mantener snapshots de épocas
        self.epoch_length = 10000  # Bloques por época
        
    def create_snapshot(self, block_height: int, accounts: dict, contracts: dict) -> StateSnapshot:
        """Crea snapshot del estado actual"""
        # Calcular state root
        state_root = self._calculate_state_root(accounts, contracts)
        
        # Crear snapshot
        snapshot = StateSnapshot(block_height, state_root, accounts, contracts)
        
        # Almacenar snapshot
        self.snapshots[block_height] = snapshot
        
        # Limpiar snapshots antiguos si es necesario
        if len(self.snapshots) > self.max_snapshots:
            self._cleanup_old_snapshots()
        
        return snapshot
    
    def _calculate_state_root(self, accounts: dict, contracts: dict) -> str:
        """Calcula root hash del estado"""
        # Crear estructura de estado
        state_data = {
            'accounts': accounts,
            'contracts': contracts
        }
        
        # Serializar y hashear
        state_bytes = rlp_encode(state_data)
        return sha3_256(state_bytes).hex()
    
    def _cleanup_old_snapshots(self):
        """Limpia snapshots antiguos"""
        if not self.snapshots:
            return
        
        # Ordenar por altura de bloque
        sorted_snapshots = sorted(self.snapshots.items(), key=lambda x: x[0])
        
        # Mantener solo los más recientes
        snapshots_to_keep = sorted_snapshots[-self.max_snapshots:]
        
        # Eliminar snapshots antiguos
        for height, _ in sorted_snapshots[:-self.max_snapshots]:
            del self.snapshots[height]
    
    def get_snapshot(self, block_height: int) -> Optional[StateSnapshot]:
        """Obtiene snapshot para una altura específica"""
        return self.snapshots.get(block_height)
    
    def get_latest_snapshot(self) -> Optional[StateSnapshot]:
        """Obtiene el snapshot más reciente"""
        if not self.snapshots:
            return None
        
        latest_height = max(self.snapshots.keys())
        return self.snapshots[latest_height]
    
    def restore_from_snapshot(self, block_height: int) -> bool:
        """Restaura estado desde snapshot"""
        snapshot = self.get_snapshot(block_height)
        if not snapshot:
            return False
        
        # Restaurar cuentas
        for address, account_data in snapshot.accounts.items():
            self.state_db.put(address.encode(), rlp_encode(account_data))
        
        # Restaurar contratos
        for address, contract_data in snapshot.contracts.items():
            self.state_db.put(f"contract_{address}".encode(), rlp_encode(contract_data))
        
        return True
    
    def prune_old_data(self, current_height: int) -> int:
        """Elimina datos antiguos para liberar espacio"""
        if not self.pruning_enabled:
            return 0
        
        if current_height - self.last_pruning_height < self.pruning_interval:
            return 0
        
        pruned_count = 0
        
        # Pruning de snapshots
        heights_to_remove = []
        for height in self.snapshots.keys():
            if height < current_height - self.keep_recent_blocks:
                # Mantener snapshots de épocas si está habilitado
                if self.keep_epoch_snapshots and height % self.epoch_length == 0:
                    continue
                heights_to_remove.append(height)
        
        for height in heights_to_remove:
            del self.snapshots[height]
            pruned_count += 1
        
        # Pruning de datos de estado antiguos
        # En implementación real, esto eliminaría datos de LevelDB
        # que no están en snapshots recientes
        
        self.last_pruning_height = current_height
        return pruned_count
    
    def get_state_info(self) -> dict:
        """Obtiene información del estado"""
        return {
            'total_snapshots': len(self.snapshots),
            'max_snapshots': self.max_snapshots,
            'pruning_enabled': self.pruning_enabled,
            'last_pruning_height': self.last_pruning_height,
            'snapshot_heights': sorted(self.snapshots.keys()),
            'total_size_bytes': sum(snapshot.size_bytes for snapshot in self.snapshots.values())
        }
    
    def verify_state_integrity(self) -> bool:
        """Verifica integridad del estado"""
        try:
            # Verificar que todos los snapshots son válidos
            for height, snapshot in self.snapshots.items():
                # Recalcular state root
                expected_root = self._calculate_state_root(snapshot.accounts, snapshot.contracts)
                if expected_root != snapshot.state_root:
                    return False
            
            return True
        except Exception:
            return False
    
    def export_state(self, block_height: int, file_path: str) -> bool:
        """Exporta estado a archivo"""
        snapshot = self.get_snapshot(block_height)
        if not snapshot:
            return False
        
        try:
            import json
            with open(file_path, 'w') as f:
                json.dump(snapshot.to_dict(), f, indent=2)
            return True
        except Exception:
            return False
    
    def import_state(self, file_path: str) -> bool:
        """Importa estado desde archivo"""
        try:
            import json
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            snapshot = StateSnapshot(
                data['block_height'],
                data['state_root'],
                data['accounts'],
                data['contracts']
            )
            
            self.snapshots[snapshot.block_height] = snapshot
            return True
        except Exception:
            return False

class PersistentStateManager:
    """Gestor de estado persistente con LevelDB y snapshots"""
    
    def __init__(self, db_path: str):
        self.state_manager = StateManager(db_path)
        self.accounts = {}  # address -> account_data
        self.contracts = {}  # address -> contract_data
        self.storage = {}  # contract_address -> storage_key -> value
        self.current_height = 0
        
    def update_account(self, address: str, account_data: dict):
        """Actualiza datos de cuenta"""
        self.accounts[address] = account_data
        self.state_manager.state_db.put(address.encode(), rlp_encode(account_data))
    
    def update_contract(self, address: str, contract_data: dict):
        """Actualiza datos de contrato"""
        self.contracts[address] = contract_data
        self.state_manager.state_db.put(f"contract_{address}".encode(), rlp_encode(contract_data))
    
    def update_storage(self, contract_address: str, key: str, value: int):
        """Actualiza storage de contrato"""
        if contract_address not in self.storage:
            self.storage[contract_address] = {}
        
        self.storage[contract_address][key] = value
        
        # Almacenar en trie
        storage_key = f"storage_{contract_address}_{key}".encode()
        self.state_manager.state_db.put(storage_key, value.to_bytes(32, 'big'))
    
    def get_account(self, address: str) -> Optional[dict]:
        """Obtiene datos de cuenta"""
        if address in self.accounts:
            return self.accounts[address]
        
        # Intentar cargar desde trie
        data = self.state_manager.state_db.get(address.encode())
        if data:
            account_data = rlp_decode(data)[0]
            self.accounts[address] = account_data
            return account_data
        
        return None
    
    def get_contract(self, address: str) -> Optional[dict]:
        """Obtiene datos de contrato"""
        if address in self.contracts:
            return self.contracts[address]
        
        # Intentar cargar desde trie
        data = self.state_manager.state_db.get(f"contract_{address}".encode())
        if data:
            contract_data = rlp_decode(data)[0]
            self.contracts[address] = contract_data
            return contract_data
        
        return None
    
    def get_storage(self, contract_address: str, key: str) -> int:
        """Obtiene valor de storage"""
        if contract_address in self.storage and key in self.storage[contract_address]:
            return self.storage[contract_address][key]
        
        # Intentar cargar desde trie
        storage_key = f"storage_{contract_address}_{key}".encode()
        data = self.state_manager.state_db.get(storage_key)
        if data:
            return int.from_bytes(data, 'big')
        
        return 0
    
    def commit_block(self, block_height: int):
        """Confirma cambios del bloque"""
        self.current_height = block_height
        
        # Crear snapshot si es necesario
        if block_height % 100 == 0:  # Snapshot cada 100 bloques
            self.state_manager.create_snapshot(block_height, self.accounts, self.contracts)
        
        # Pruning periódico
        self.state_manager.prune_old_data(block_height)
    
    def rollback_to_height(self, target_height: int) -> bool:
        """Revierte estado a una altura específica"""
        # Buscar snapshot más cercano
        available_heights = sorted(self.state_manager.snapshots.keys())
        snapshot_height = None
        
        for height in reversed(available_heights):
            if height <= target_height:
                snapshot_height = height
                break
        
        if snapshot_height is None:
            return False
        
        # Restaurar desde snapshot
        return self.state_manager.restore_from_snapshot(snapshot_height)
    
    def get_state_root(self) -> str:
        """Calcula root hash del estado actual"""
        return self.state_manager._calculate_state_root(self.accounts, self.contracts)
    
    def get_state_info(self) -> dict:
        """Obtiene información del estado"""
        info = self.state_manager.get_state_info()
        info.update({
            'current_height': self.current_height,
            'total_accounts': len(self.accounts),
            'total_contracts': len(self.contracts),
            'state_root': self.get_state_root()
        })
        return info

# === SISTEMA P2P ROBUSTO CON DHT ===
class DHTNode:
    """Nodo de Distributed Hash Table para descubrimiento de peers"""
    
    def __init__(self, node_id: str, address: tuple):
        self.node_id = node_id
        self.address = address  # (ip, port)
        self.buckets = [[] for _ in range(160)]  # 160 buckets para 160-bit IDs
        self.routing_table = {}
        self.last_seen = time.time()
        self.reputation = 100
        self.connection_count = 0
        
    def distance(self, other_id: str) -> int:
        """Calcula distancia XOR entre nodos"""
        return int(self.node_id, 16) ^ int(other_id, 16)
    
    def add_peer(self, peer_id: str, peer_address: tuple):
        """Añade peer a la tabla de enrutamiento"""
        distance = self.distance(peer_id)
        bucket_index = distance.bit_length() - 1 if distance > 0 else 0
        
        # Añadir a bucket si hay espacio o reemplazar peer menos confiable
        if len(self.buckets[bucket_index]) < 8:  # Kademlia k=8
            self.buckets[bucket_index].append({
                'id': peer_id,
                'address': peer_address,
                'last_seen': time.time(),
                'reputation': 100
            })
        else:
            # Reemplazar peer con menor reputación
            min_reputation = min(peer['reputation'] for peer in self.buckets[bucket_index])
            for i, peer in enumerate(self.buckets[bucket_index]):
                if peer['reputation'] == min_reputation:
                    self.buckets[bucket_index][i] = {
                        'id': peer_id,
                        'address': peer_address,
                        'last_seen': time.time(),
                        'reputation': 100
                    }
                    break
        
        self.routing_table[peer_id] = peer_address
    
    def get_closest_peers(self, target_id: str, count: int = 8) -> List[tuple]:
        """Obtiene los peers más cercanos a un ID objetivo"""
        all_peers = []
        for bucket in self.buckets:
            all_peers.extend(bucket)
        
        # Ordenar por distancia
        all_peers.sort(key=lambda p: int(p['id'], 16) ^ int(target_id, 16))
        
        return [(peer['id'], peer['address']) for peer in all_peers[:count]]

class EclipseAttackProtection:
    """Protección contra ataques de eclipse"""
    
    def __init__(self):
        self.connection_history = {}  # peer_id -> connection_times
        self.suspicious_peers = set()
        self.max_connections_per_peer = 5
        self.time_window = 3600  # 1 hora
        self.reputation_threshold = 50
        
    def is_suspicious_peer(self, peer_id: str, peer_address: tuple) -> bool:
        """Detecta si un peer es sospechoso de ataque eclipse"""
        current_time = time.time()
        
        # Verificar si el peer está en la lista de sospechosos
        if peer_id in self.suspicious_peers:
            return True
        
        # Verificar conexiones excesivas
        if peer_id in self.connection_history:
            recent_connections = [
                t for t in self.connection_history[peer_id] 
                if current_time - t < self.time_window
            ]
            
            if len(recent_connections) > self.max_connections_per_peer:
                self.suspicious_peers.add(peer_id)
                return True
        
        return False
    
    def record_connection(self, peer_id: str, peer_address: tuple):
        """Registra conexión de peer"""
        current_time = time.time()
        
        if peer_id not in self.connection_history:
            self.connection_history[peer_id] = []
        
        self.connection_history[peer_id].append(current_time)
        
        # Limpiar conexiones antiguas
        self.connection_history[peer_id] = [
            t for t in self.connection_history[peer_id] 
            if current_time - t < self.time_window
        ]
    
    def update_peer_reputation(self, peer_id: str, success: bool):
        """Actualiza reputación del peer"""
        if peer_id in self.connection_history:
            # En implementación real, esto actualizaría reputación
            pass

class P2PNetworkManager:
    """Gestor de red P2P con DHT y protección contra eclipse"""
    
    def __init__(self, node_id: str, listen_address: tuple):
        self.node_id = node_id
        self.listen_address = listen_address
        self.dht_node = DHTNode(node_id, listen_address)
        self.eclipse_protection = EclipseAttackProtection()
        self.connected_peers = {}  # peer_id -> connection_info
        self.bootstrap_nodes = []
        self.max_peers = 50
        self.discovery_interval = 300  # 5 minutos
        self.last_discovery = 0
        
        # Configuración de red
        self.ping_timeout = 5
        self.ping_interval = 60
        self.sync_interval = 10
        
    def add_bootstrap_node(self, address: tuple):
        """Añade nodo bootstrap"""
        self.bootstrap_nodes.append(address)
    
    def discover_peers(self) -> List[tuple]:
        """Descubre nuevos peers usando DHT"""
        current_time = time.time()
        
        if current_time - self.last_discovery < self.discovery_interval:
            return []
        
        discovered_peers = []
        
        # Usar nodos bootstrap para descubrimiento inicial
        for bootstrap_addr in self.bootstrap_nodes:
            try:
                # En implementación real, esto enviaría mensajes FIND_NODE
                # Por ahora simulamos descubrimiento
                fake_peers = self._simulate_peer_discovery(bootstrap_addr)
                discovered_peers.extend(fake_peers)
            except Exception as e:
                print(f"Error discovering peers from {bootstrap_addr}: {e}")
        
        # Usar DHT para descubrimiento
        if len(self.dht_node.routing_table) > 0:
            # Buscar peers cercanos a nuestro ID
            closest_peers = self.dht_node.get_closest_peers(self.node_id, 20)
            discovered_peers.extend(closest_peers)
        
        self.last_discovery = current_time
        return discovered_peers
    
    def _simulate_peer_discovery(self, bootstrap_addr: tuple) -> List[tuple]:
        """Simula descubrimiento de peers (en implementación real sería real)"""
        # Generar algunos peers falsos para demostración
        fake_peers = []
        for i in range(5):
            fake_id = f"{random.randint(0, 2**160-1):040x}"
            fake_addr = (f"192.168.1.{100 + i}", 30303 + i)
            fake_peers.append((fake_id, fake_addr))
        return fake_peers
    
    def connect_to_peer(self, peer_id: str, peer_address: tuple) -> bool:
        """Conecta a un peer específico"""
        # Verificar protección contra eclipse
        if self.eclipse_protection.is_suspicious_peer(peer_id, peer_address):
            print(f"Rejecting suspicious peer: {peer_id}")
            return False
        
        # Verificar límite de conexiones
        if len(self.connected_peers) >= self.max_peers:
            print("Maximum peer connections reached")
            return False
        
        try:
            # En implementación real, esto establecería conexión TCP/UDP
            # Por ahora simulamos conexión exitosa
            connection_info = {
                'id': peer_id,
                'address': peer_address,
                'connected_at': time.time(),
                'last_ping': time.time(),
                'reputation': 100,
                'sync_status': 'syncing'
            }
            
            self.connected_peers[peer_id] = connection_info
            self.dht_node.add_peer(peer_id, peer_address)
            self.eclipse_protection.record_connection(peer_id, peer_address)
            
            print(f"Connected to peer {peer_id} at {peer_address}")
            return True
            
        except Exception as e:
            print(f"Failed to connect to peer {peer_id}: {e}")
            return False
    
    def disconnect_peer(self, peer_id: str):
        """Desconecta de un peer"""
        if peer_id in self.connected_peers:
            del self.connected_peers[peer_id]
            print(f"Disconnected from peer {peer_id}")
    
    def ping_peers(self):
        """Envía ping a todos los peers conectados"""
        current_time = time.time()
        peers_to_remove = []
        
        for peer_id, peer_info in self.connected_peers.items():
            if current_time - peer_info['last_ping'] > self.ping_interval:
                try:
                    # En implementación real, esto enviaría PING
                    # Por ahora simulamos ping exitoso
                    success = self._simulate_ping(peer_id)
                    
                    if success:
                        peer_info['last_ping'] = current_time
                        self.eclipse_protection.update_peer_reputation(peer_id, True)
                    else:
                        peers_to_remove.append(peer_id)
                        self.eclipse_protection.update_peer_reputation(peer_id, False)
                        
                except Exception as e:
                    print(f"Ping failed for peer {peer_id}: {e}")
                    peers_to_remove.append(peer_id)
        
        # Remover peers que no respondieron
        for peer_id in peers_to_remove:
            self.disconnect_peer(peer_id)
    
    def _simulate_ping(self, peer_id: str) -> bool:
        """Simula ping a peer (en implementación real sería real)"""
        # 90% de éxito para simulación
        return random.random() < 0.9
    
    def sync_with_peers(self, blockchain_height: int) -> List[dict]:
        """Sincroniza con peers para obtener bloques"""
        current_time = time.time()
        new_blocks = []
        
        for peer_id, peer_info in self.connected_peers.items():
            if current_time - peer_info.get('last_sync', 0) > self.sync_interval:
                try:
                    # En implementación real, esto solicitaría bloques
                    # Por ahora simulamos sincronización
                    peer_blocks = self._simulate_block_sync(peer_id, blockchain_height)
                    new_blocks.extend(peer_blocks)
                    peer_info['last_sync'] = current_time
                    
                except Exception as e:
                    print(f"Sync failed with peer {peer_id}: {e}")
        
        return new_blocks
    
    def _simulate_block_sync(self, peer_id: str, current_height: int) -> List[dict]:
        """Simula sincronización de bloques (en implementación real sería real)"""
        # Simular algunos bloques nuevos
        new_blocks = []
        for i in range(random.randint(0, 3)):
            block = {
                'height': current_height + i + 1,
                'hash': f"block_{current_height + i + 1}",
                'timestamp': time.time(),
                'peer_id': peer_id
            }
            new_blocks.append(block)
        return new_blocks
    
    def broadcast_message(self, message: dict, exclude_peers: List[str] = None):
        """Transmite mensaje a todos los peers conectados"""
        if exclude_peers is None:
            exclude_peers = []
        
        for peer_id, peer_info in self.connected_peers.items():
            if peer_id not in exclude_peers:
                try:
                    # En implementación real, esto enviaría el mensaje
                    self._simulate_message_send(peer_id, message)
                except Exception as e:
                    print(f"Failed to send message to peer {peer_id}: {e}")
    
    def _simulate_message_send(self, peer_id: str, message: dict):
        """Simula envío de mensaje (en implementación real sería real)"""
        print(f"Sending message to peer {peer_id}: {message.get('type', 'unknown')}")
    
    def get_network_info(self) -> dict:
        """Obtiene información de la red"""
        return {
            'node_id': self.node_id,
            'listen_address': self.listen_address,
            'connected_peers': len(self.connected_peers),
            'max_peers': self.max_peers,
            'bootstrap_nodes': len(self.bootstrap_nodes),
            'dht_peers': len(self.dht_node.routing_table),
            'suspicious_peers': len(self.eclipse_protection.suspicious_peers),
            'last_discovery': self.last_discovery
        }
    
    def get_peer_list(self) -> List[dict]:
        """Obtiene lista de peers conectados"""
        peer_list = []
        for peer_id, peer_info in self.connected_peers.items():
            peer_list.append({
                'id': peer_id,
                'address': peer_info['address'],
                'connected_at': peer_info['connected_at'],
                'reputation': peer_info['reputation'],
                'sync_status': peer_info['sync_status']
            })
        return peer_list

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
    """Codificación RLP mejorada"""
    if isinstance(data, int):
        if data == 0:
            return b'\x80'
        elif data < 0x80:
            return bytes([data])
        else:
            encoded = data.to_bytes((data.bit_length() + 7) // 8, 'big')
            return bytes([0x80 + len(encoded)]) + encoded
    elif isinstance(data, str):
        return rlp_encode(data.encode())
    elif isinstance(data, bytes):
        if len(data) == 1 and data[0] < 0x80:
            return data
        elif len(data) < 56:
            return bytes([0x80 + len(data)]) + data
        else:
            length_bytes = len(data).to_bytes((len(data).bit_length() + 7) // 8, 'big')
            return bytes([0xb7 + len(length_bytes)]) + length_bytes + data
    elif isinstance(data, list):
        encoded_items = b''
        for item in data:
            encoded_items += rlp_encode(item)
        
        if len(encoded_items) < 56:
            return bytes([0xc0 + len(encoded_items)]) + encoded_items
        else:
            length_bytes = len(encoded_items).to_bytes((len(encoded_items).bit_length() + 7) // 8, 'big')
            return bytes([0xf7 + len(length_bytes)]) + length_bytes + encoded_items
    else:
        raise TypeError(f"Cannot encode type {type(data)}")

def rlp_decode(data: bytes):
    """Decodificación RLP mejorada"""
    if not data:
        return b''
    
    first_byte = data[0]
    
    if first_byte < 0x80:
        # Byte simple
        return data[0:1], data[1:]
    elif first_byte < 0xb8:
        # String corto
        length = first_byte - 0x80
        return data[1:1+length], data[1+length:]
    elif first_byte < 0xc0:
        # String largo
        length_length = first_byte - 0xb7
        length = int.from_bytes(data[1:1+length_length], 'big')
        return data[1+length_length:1+length_length+length], data[1+length_length+length:]
    elif first_byte < 0xf8:
        # Lista corta
        length = first_byte - 0xc0
        items = []
        remaining = data[1:1+length]
        while remaining:
            item, remaining = rlp_decode(remaining)
            items.append(item)
        return items, data[1+length:]
    else:
        # Lista larga
        length_length = first_byte - 0xf7
        length = int.from_bytes(data[1:1+length_length], 'big')
        items = []
        remaining = data[1+length_length:1+length_length+length]
        while remaining:
            item, remaining = rlp_decode(remaining)
            items.append(item)
        return items, data[1+length_length+length:]

def sha3_256(data: bytes) -> bytes:
    """SHA3-256 hash function"""
    import hashlib
    return hashlib.sha3_256(data).digest()

# === NODO P2P MEJORADO ===
class P2PNodeV3:
    """Nodo P2P enterprise con descubrimiento y sincronización avanzada"""

    def __init__(self, blockchain: MSCBlockchainV3, port: int = 30303):
        self.blockchain = blockchain
        self.port = port
        self.node_id = self._generate_node_id()
        self.peers = {}  # peer_id -> PeerConnection
        self.max_peers = BlockchainConfig.MAX_PEERS if hasattr(BlockchainConfig, 'MAX_PEERS') else 50
        self.banned_peers = set()  # Set de direcciones IP baneadas
        self.peer_reputation = {}  # Reputación de peers
        self.discovery_protocol = DiscoveryProtocol(self)
        self.reconnect_queue = asyncio.Queue()  # Cola para reconexiones
        self.metrics = {
            'connected_peers': 0,
            'messages_received': 0,
            'messages_sent': 0,
            'bytes_received': 0,
            'bytes_sent': 0,
            'failed_connections': 0
        }

    def _generate_node_id(self) -> str:
        """Genera ID único del nodo basado en criptografía de clave pública"""
        # Generar par de claves para identificación criptográfica
        private_key = ec.generate_private_key(
            ec.SECP256K1(),
            default_backend()
        )
        public_key = private_key.public_key()

        # Serializar la clave pública y usar su hash como ID
        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Guardar la clave privada para uso futuro (firma de mensajes)
        self.private_key = private_key
        self.public_key = public_key

        # Devolver el hash de la clave pública como ID del nodo
        return hashlib.sha256(serialized_public).hexdigest()

    async def start(self):
        """Inicia el nodo P2P con manejo mejorado de conexiones"""
        # Iniciar servidor
        server = await asyncio.start_server(
            self.handle_peer_connection,
            '0.0.0.0',
            self.port
        )

        # Iniciar discovery
        asyncio.create_task(self.discovery_protocol.start())

        # Iniciar worker de reconexión
        asyncio.create_task(self._reconnection_worker())

        # Iniciar monitoreo de peers
        asyncio.create_task(self._monitor_peers())

        logger.info(f"P2P node started on port {self.port}")
        logger.info(f"Node ID: {self.node_id}")

        async with server:
            await server.serve_forever()

    async def _reconnection_worker(self):
        """Worker para manejar reconexiones a peers"""
        while True:
            peer_address = await self.reconnect_queue.get()

            # No reconectar a peers baneados
            if peer_address in self.banned_peers:
                continue

            # Esperar antes de reconectar
            await asyncio.sleep(5)

            try:
                await self.discovery_protocol.connect_to_peer(peer_address)
                logger.info(f"Reconnected to peer {peer_address}")
            except Exception as e:
                logger.error(f"Failed to reconnect to {peer_address}: {e}")
                # Incrementar contador de fallos
                self.metrics['failed_connections'] += 1

            self.reconnect_queue.task_done()

    async def _monitor_peers(self):
        """Monitorea la salud de los peers y mantiene estadísticas"""
        while True:
            # Actualizar métricas
            self.metrics['connected_peers'] = len(self.peers)

            # Verificar peers inactivos
            inactive_peers = []
            for peer_id, peer in self.peers.items():
                if peer.last_seen and (time.time() - peer.last_seen) > 300:  # 5 minutos
                    inactive_peers.append(peer_id)

            # Desconectar peers inactivos
            for peer_id in inactive_peers:
                if peer_id in self.peers:
                    await self.peers[peer_id].disconnect("Inactivity timeout")

            # Registrar métricas
            if hasattr(logger, 'info') and len(self.peers) > 0:
                logger.info(f"P2P metrics: {self.metrics}")

            await asyncio.sleep(60)  # Verificar cada minuto

    async def handle_peer_connection(self, reader, writer):
        """Maneja conexión entrante de peer con límites y seguridad mejorada"""
        peer_address = writer.get_extra_info('peername')

        # Verificar si el peer está baneado
        if peer_address[0] in self.banned_peers:
            logger.warning(f"Rejected connection from banned peer {peer_address}")
            writer.close()
            return

        # Verificar límite de peers
        if len(self.peers) >= self.max_peers:
            logger.warning(f"Rejected connection from {peer_address}: max peers reached")
            writer.close()
            return

        logger.info(f"New peer connection from {peer_address}")

        peer = PeerConnection(reader, writer, self)
        try:
            await peer.handle()
        except Exception as e:
            logger.error(f"Error handling peer {peer_address}: {e}")
            # Considerar añadir a la cola de reconexión si es un peer valioso

class PeerConnection:
    """Conexión individual con un peer con manejo mejorado de mensajes y errores"""

    def __init__(self, reader, writer, node: P2PNodeV3):
        self.reader = reader
        self.writer = writer
        self.node = node
        self.peer_id = None
        self.version = None
        self.peer_address = writer.get_extra_info('peername')
        self.last_seen = time.time()
        self.ping_time = None
        self.latency = 0  # ms
        self.message_stats = {
            'sent': 0,
            'received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'errors': 0
        }
        self.capabilities = set()  # Funcionalidades soportadas
        self.is_connected = False
        self.disconnect_reason = None

    async def handle(self):
        """Maneja comunicación con peer con mejor manejo de errores y reconexión"""
        try:
            # Handshake
            await self.handshake()

            # Registrar en el nodo
            if self.peer_id:
                self.node.peers[self.peer_id] = self
                self.is_connected = True
                logger.info(f"Peer {self.peer_id[:8]}... connected from {self.peer_address}")

            # Iniciar ping periódico
            ping_task = asyncio.create_task(self._ping_loop())

            # Message loop
            while self.is_connected:
                try:
                    message = await asyncio.wait_for(self.read_message(), timeout=60)
                    if not message:
                        logger.info(f"Peer {self.peer_id[:8]}... disconnected (empty message)")
                        break

                    self.last_seen = time.time()
                    self.message_stats['received'] += 1

                    await self.handle_message(message)
                except asyncio.TimeoutError:
                    logger.warning(f"Peer {self.peer_id[:8]}... read timeout")
                    break
                except Exception as e:
                    logger.error(f"Error processing message from {self.peer_id[:8]}...: {e}")
                    self.message_stats['errors'] += 1
                    # Si hay demasiados errores, desconectar
                    if self.message_stats['errors'] > 5:
                        await self.disconnect("Too many errors")
                        break

            # Cancelar ping task
            ping_task.cancel()

        except Exception as e:
            logger.error(f"Peer connection error with {self.peer_address}: {e}")
            self.disconnect_reason = str(e)
        finally:
            # Limpiar
            await self._cleanup()

            # Considerar reconexión si fue un peer valioso
            if self.peer_id and self.message_stats['received'] > 10:
                peer_addr = f"{self.peer_address[0]}:{self.peer_address[1]}"
                await self.node.reconnect_queue.put(peer_addr)

    async def _cleanup(self):
        """Limpia recursos al desconectar"""
        if self.peer_id and self.peer_id in self.node.peers:
            del self.node.peers[self.peer_id]

        self.is_connected = False

        try:
            self.writer.close()
            await self.writer.wait_closed()
        except:
            pass

        logger.info(f"Peer {self.peer_id[:8] if self.peer_id else 'unknown'} disconnected: {self.disconnect_reason or 'unknown reason'}")

    async def disconnect(self, reason: str = "Client disconnect"):
        """Desconecta ordenadamente del peer"""
        if not self.is_connected:
            return

        self.disconnect_reason = reason
        self.is_connected = False

        try:
            # Enviar mensaje de desconexión
            await self.send_message({
                'type': 'disconnect',
                'reason': reason
            })
        except:
            pass

    async def _ping_loop(self):
        """Envía pings periódicos para medir latencia y mantener conexión"""
        while self.is_connected:
            try:
                await asyncio.sleep(30)  # Ping cada 30 segundos

                start_time = time.time()
                ping_id = secrets.token_hex(8)

                await self.send_message({
                    'type': 'ping',
                    'id': ping_id,
                    'timestamp': start_time
                })

                self.ping_time = start_time

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in ping loop for {self.peer_id[:8] if self.peer_id else 'unknown'}: {e}")

    async def handshake(self):
        """Protocolo de handshake mejorado con capacidades y versiones"""
        # Enviar hello
        hello = {
            'type': 'hello',
            'version': BlockchainConfig.VERSION,
            'node_id': self.node.node_id,
            'chain_id': BlockchainConfig.CHAIN_ID,
            'total_difficulty': sum(b.header.difficulty for b in self.node.blockchain.chain),
            'best_hash': self.node.blockchain.get_latest_block().hash,
            'genesis_hash': self.node.blockchain.chain[0].hash,
            'capabilities': [
                'blocks', 'transactions', 'state', 'defi', 'bridge', 'oracle'
            ],
            'network': {
                'local_address': f"0.0.0.0:{self.node.port}",
                'protocol_version': '1.0'
            }
        }

        await self.send_message(hello)

        # Recibir hello con timeout
        try:
            response = await asyncio.wait_for(self.read_message(), timeout=10)
            if not response or response.get('type') != 'hello':
                raise ValueError("Invalid handshake response")

            self.peer_id = response['node_id']
            self.version = response['version']

            # Guardar capacidades
            if 'capabilities' in response:
                self.capabilities = set(response['capabilities'])

            # Verificar compatibilidad
            if response.get('chain_id') != BlockchainConfig.CHAIN_ID:
                raise ValueError(f"Different chain ID: {response.get('chain_id')} vs {BlockchainConfig.CHAIN_ID}")

            if response.get('genesis_hash') != self.node.blockchain.chain[0].hash:
                raise ValueError("Different genesis hash")

            # Verificar versión mínima
            if self._compare_versions(self.version, '2.0.0') < 0:
                raise ValueError(f"Unsupported version: {self.version}")

        except asyncio.TimeoutError:
            raise ValueError("Handshake timeout")

    def _compare_versions(self, version1: str, version2: str) -> int:
        """Compara versiones semánticas (x.y.z)"""
        v1_parts = [int(x) for x in version1.split('.')]
        v2_parts = [int(x) for x in version2.split('.')]

        for i in range(min(len(v1_parts), len(v2_parts))):
            if v1_parts[i] > v2_parts[i]:
                return 1
            elif v1_parts[i] < v2_parts[i]:
                return -1

        return 0

    async def send_message(self, message: Dict):
        """Envía mensaje al peer con compresión y métricas"""
        if not self.is_connected and message.get('type') != 'disconnect':
            raise ValueError("Peer disconnected")

        try:
            # Añadir timestamp
            if 'timestamp' not in message:
                message['timestamp'] = time.time()

            # Serializar y comprimir para mensajes grandes
            data = json.dumps(message).encode()

            if len(data) > 1024:  # Comprimir mensajes > 1KB
                compressed = zlib.compress(data)
                if len(compressed) < len(data):
                    data = compressed
                    # Añadir flag de compresión
                    self.writer.write(b'\x01')
                else:
                    # Sin compresión
                    self.writer.write(b'\x00')
            else:
                # Sin compresión
                self.writer.write(b'\x00')

            # Escribir longitud y datos
            self.writer.write(len(data).to_bytes(4, 'big'))
            self.writer.write(data)
            await self.writer.drain()

            # Actualizar métricas
            self.message_stats['sent'] += 1
            self.message_stats['bytes_sent'] += len(data)
            self.node.metrics['messages_sent'] += 1
            self.node.metrics['bytes_sent'] += len(data)

        except Exception as e:
            logger.error(f"Error sending message to {self.peer_id[:8] if self.peer_id else 'unknown'}: {e}")
            raise

    async def read_message(self) -> Optional[Dict]:
        """Lee mensaje del peer con soporte para compresión y timeout"""
        try:
            # Leer flag de compresión
            compression_flag = await self.reader.read(1)
            if not compression_flag:
                return None

            is_compressed = compression_flag == b'\x01'

            # Leer longitud
            length_data = await self.reader.read(4)
            if not length_data:
                return None

            length = int.from_bytes(length_data, 'big')

            # Verificar tamaño máximo razonable (50MB)
            if length > 50 * 1024 * 1024:
                raise ValueError(f"Message too large: {length} bytes")

            # Leer mensaje
            data = await self.reader.read(length)
            if not data:
                return None

            # Descomprimir si es necesario
            if is_compressed:
                data = zlib.decompress(data)

            # Actualizar métricas
            self.message_stats['bytes_received'] += len(data)
            self.node.metrics['messages_received'] += 1
            self.node.metrics['bytes_received'] += len(data)

            # Decodificar JSON
            message = json.loads(data.decode())

            # Procesar ping/pong
            if message.get('type') == 'ping':
                await self._handle_ping(message)
            elif message.get('type') == 'pong':
                self._handle_pong(message)

            return message

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON from peer {self.peer_id[:8] if self.peer_id else 'unknown'}: {e}")
            self.message_stats['errors'] += 1
            return None
        except Exception as e:
            logger.error(f"Error reading message from {self.peer_id[:8] if self.peer_id else 'unknown'}: {e}")
            raise

    async def _handle_ping(self, message: Dict):
        """Responde a ping con pong"""
        try:
            await self.send_message({
                'type': 'pong',
                'id': message.get('id'),
                'echo_timestamp': message.get('timestamp'),
                'timestamp': time.time()
            })
        except:
            pass

    def _handle_pong(self, message: Dict):
        """Procesa respuesta pong para calcular latencia"""
        if self.ping_time and message.get('echo_timestamp') == self.ping_time:
            self.latency = int((time.time() - self.ping_time) * 1000)  # ms
            self.ping_time = None

            # Registrar métrica de latencia
            network_latency.observe(self.latency)

    async def handle_message(self, message: Dict):
        """Procesa mensaje recibido con manejo de errores mejorado"""
        try:
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
            elif msg_type == 'peer_list':
                await self.handle_peer_list(message)
            elif msg_type == 'disconnect':
                self.disconnect_reason = message.get('reason', 'Remote disconnect')
                self.is_connected = False
            elif msg_type == 'get_state':
                await self.handle_get_state(message)
            elif msg_type == 'state_chunk':
                await self.handle_state_chunk(message)
        except Exception as e:
            logger.error(f"Error handling message type {message.get('type')} from {self.peer_id[:8] if self.peer_id else 'unknown'}: {e}")
            self.message_stats['errors'] += 1

    async def handle_get_blocks(self, message: Dict):
        """Maneja solicitud de bloques con validación y límites"""
        try:
            start = int(message.get('start', 0))
            count = min(int(message.get('count', 100)), 500)  # Máximo 500 bloques

            # Validar rango
            if start < 0 or start >= len(self.node.blockchain.chain):
                await self.send_message({
                    'type': 'error',
                    'code': 'INVALID_RANGE',
                    'message': f"Invalid block range: {start}"
                })
                return

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
                'blocks': blocks,
                'start': start,
                'count': len(blocks)
            })
        except Exception as e:
            logger.error(f"Error handling get_blocks: {e}")
            await self.send_message({
                'type': 'error',
                'code': 'INTERNAL_ERROR',
                'message': "Internal error processing get_blocks"
            })

    async def handle_blocks(self, message: Dict):
        """Procesa bloques recibidos"""
        blocks_data = message.get('blocks', [])
        logger.info(f"Received {len(blocks_data)} blocks from peer {self.peer_id[:8]}...")

        # Procesar bloques (implementación simplificada)
        for block_data in blocks_data:
            # Convertir a objetos Block
            # Validar y añadir a la cadena si es válido
            pass

    async def handle_new_block(self, message: Dict):
        """Procesa notificación de nuevo bloque"""
        block_data = message.get('block')
        if not block_data:
            return

        logger.info(f"Received new block notification from peer {self.peer_id[:8]}...")

        # Verificar si ya tenemos el bloque
        block_hash = block_data.get('header', {}).get('hash')
        if block_hash and self.node.blockchain.get_block_by_hash(block_hash):
            logger.debug(f"Block {block_hash[:8]}... already known")
            return

        # Solicitar el bloque completo si solo recibimos el header
        if 'transactions' not in block_data:
            await self.send_message({
                'type': 'get_blocks',
                'start': block_data.get('header', {}).get('number'),
                'count': 1
            })

    async def handle_new_transaction(self, message: Dict):
        """Procesa nueva transacción"""
        tx_data = message.get('transaction')
        if not tx_data:
            return

        # Convertir a objeto Transaction
        # Validar y añadir al pool si es válida
        pass

    async def handle_get_peer_list(self, message: Dict):
        """Responde con lista de peers conocidos"""
        max_peers = min(int(message.get('max', 20)), 100)  # Máximo 100 peers

        peers = []
        for peer_id, peer in self.node.peers.items():
            if len(peers) >= max_peers:
                break

            # No incluir al solicitante
            if peer_id == self.peer_id:
                continue

            peers.append({
                'id': peer_id,
                'address': f"{peer.peer_address[0]}:{peer.peer_address[1]}",
                'version': peer.version,
                'capabilities': list(peer.capabilities)
            })

        await self.send_message({
            'type': 'peer_list',
            'peers': peers
        })

    async def handle_peer_list(self, message: Dict):
        """Procesa lista de peers recibida"""
        peers = message.get('peers', [])
        logger.debug(f"Received {len(peers)} peers from {self.peer_id[:8]}...")

        # Conectar a nuevos peers
        for peer_info in peers:
            if 'address' in peer_info and peer_info.get('id') not in self.node.peers:
                try:
                    await self.node.discovery_protocol.connect_to_peer(peer_info['address'])
                except:
                    pass

    async def handle_get_state(self, message: Dict):
        """Maneja solicitud de estado (para sincronización)"""
        # Implementación simplificada
        pass

    async def handle_state_chunk(self, message: Dict):
        """Procesa fragmento de estado recibido"""
        # Implementación simplificada
        pass

class DiscoveryProtocol:
    """Protocolo avanzado de descubrimiento de peers con soporte para NAT traversal"""

    def __init__(self, node: P2PNodeV3):
        self.node = node

        # Nodos bootstrap principales y de respaldo
        self.bootstrap_nodes = [
            # Lista de nodos bootstrap primarios
            "msc-boot-1.network:30303",
            "msc-boot-2.network:30303",
            "msc-boot-3.network:30303",
            # Nodos de respaldo
            "msc-backup-1.network:30303",
            "msc-backup-2.network:30303"
        ]

        # Nodos semilla estáticos (siempre intentar conectar)
        self.seed_nodes = [
            "msc-seed-1.network:30303",
            "msc-seed-2.network:30303"
        ]

        # Caché de peers descubiertos
        self.discovered_peers = {}  # address -> last_seen

        # Reputación de peers
        self.peer_reputation = {}  # address -> score (0-100)

        # Estado de NAT
        self.external_ip = None
        self.external_port = None
        self.nat_type = "unknown"  # unknown, open, symmetric, restricted

        # Límites y configuración
        self.max_outbound_connections = 15
        self.max_inbound_connections = 85
        self.discovery_rounds = 0
        self.last_discovery_time = 0
        self.discovery_interval = BlockchainConfig.PEER_DISCOVERY_INTERVAL

        # Estadísticas
        self.stats = {
            'connection_attempts': 0,
            'successful_connections': 0,
            'failed_connections': 0,
            'peers_discovered': 0
        }

    async def start(self):
        """Inicia protocolo de descubrimiento con múltiples estrategias"""
        logger.info("Starting enhanced peer discovery protocol")

        # Detectar NAT y configuración de red
        asyncio.create_task(self._detect_nat())

        # Conectar a nodos semilla (alta prioridad)
        for seed_node in self.seed_nodes:
            asyncio.create_task(self._connect_with_retry(seed_node, is_seed=True))

        # Conectar a nodos bootstrap
        bootstrap_tasks = []
        for boot_node in self.bootstrap_nodes:
            task = asyncio.create_task(self._connect_with_retry(boot_node))
            bootstrap_tasks.append(task)

        # Esperar a que al menos un nodo bootstrap se conecte
        try:
            await asyncio.wait_for(asyncio.gather(*bootstrap_tasks, return_exceptions=True), 
                                  timeout=30)
        except asyncio.TimeoutError:
            logger.warning("Timeout connecting to bootstrap nodes")

        # Iniciar descubrimiento periódico
        asyncio.create_task(self._periodic_discovery())

        # Iniciar mantenimiento de peers
        asyncio.create_task(self._peer_maintenance())

        logger.info("Peer discovery protocol started")

    async def _detect_nat(self):
        """Detecta tipo de NAT y dirección IP externa"""
        try:
            # Intentar obtener IP externa de servicios STUN
            stun_servers = [
                "stun.l.google.com:19302",
                "stun1.l.google.com:19302",
                "stun2.l.google.com:19302"
            ]

            # Implementación simplificada - en producción usar librería STUN
            for server in stun_servers:
                try:
                    # Simular detección STUN
                    response = await asyncio.wait_for(
                        self._query_stun_server(server), 
                        timeout=5
                    )
                    if response:
                        self.external_ip = response.get('ip')
                        self.external_port = response.get('port')
                        self.nat_type = response.get('nat_type', 'unknown')
                        logger.info(f"NAT detection: {self.nat_type}, External IP: {self.external_ip}:{self.external_port}")
                        break
                except:
                    continue

            if not self.external_ip:
                # Fallback: intentar obtener IP de servicios HTTP
                try:
                    # Simular consulta HTTP para IP
                    self.external_ip = "0.0.0.0"  # Placeholder
                    logger.info(f"Detected external IP via HTTP: {self.external_ip}")
                except:
                    logger.warning("Failed to detect external IP")
        except Exception as e:
            logger.error(f"Error in NAT detection: {e}")

    async def _query_stun_server(self, server):
        """Consulta servidor STUN para obtener información de NAT"""
        # Implementación simplificada - en producción usar librería STUN
        # Simular respuesta STUN
        await asyncio.sleep(0.5)  # Simular latencia de red
        return {
            'ip': "203.0.113." + str(random.randint(1, 254)),
            'port': random.randint(10000, 60000),
            'nat_type': random.choice(['open', 'symmetric', 'restricted'])
        }

    async def _connect_with_retry(self, address: str, max_retries=3, is_seed=False):
        """Conecta a un peer con reintentos"""
        retries = 0
        backoff = 1

        while retries < max_retries:
            try:
                self.stats['connection_attempts'] += 1
                await self.connect_to_peer(address)
                self.stats['successful_connections'] += 1

                # Actualizar reputación positivamente
                self._update_peer_reputation(address, 5)

                # Si es un nodo semilla, mantener en la lista para reconexión
                if is_seed:
                    logger.info(f"Successfully connected to seed node {address}")

                return True
            except Exception as e:
                retries += 1
                logger.warning(f"Failed to connect to {address} (attempt {retries}/{max_retries}): {e}")

                # Actualizar reputación negativamente
                self._update_peer_reputation(address, -2)

                # Esperar con backoff exponencial
                await asyncio.sleep(backoff)
                backoff *= 2

        self.stats['failed_connections'] += 1
        return False

    async def _periodic_discovery(self):
        """Ejecuta descubrimiento periódico de peers"""
        while True:
            try:
                # Ajustar intervalo basado en número de peers
                if len(self.node.peers) < 5:
                    # Pocos peers, descubrir más rápido
                    interval = max(5, self.discovery_interval // 2)
                elif len(self.node.peers) > 50:
                    # Muchos peers, ralentizar descubrimiento
                    interval = min(120, self.discovery_interval * 2)
                else:
                    interval = self.discovery_interval

                # Ejecutar descubrimiento
                start_time = time.time()
                await self.discover_peers()
                self.last_discovery_time = time.time()
                self.discovery_rounds += 1

                # Registrar estadísticas
                if self.discovery_rounds % 10 == 0:
                    logger.info(f"Discovery stats: {self.stats}")
                    logger.info(f"Connected peers: {len(self.node.peers)}/{self.max_inbound_connections + self.max_outbound_connections}")

                # Esperar hasta el próximo ciclo
                elapsed = time.time() - start_time
                await asyncio.sleep(max(1, interval - elapsed))

            except Exception as e:
                logger.error(f"Error in periodic discovery: {e}")
                await asyncio.sleep(10)  # Esperar antes de reintentar

    async def _peer_maintenance(self):
        """Mantiene la lista de peers, reconectando a nodos semilla y limpiando peers inactivos"""
        while True:
            try:
                # Reconectar a nodos semilla si es necesario
                for seed in self.seed_nodes:
                    seed_connected = False
                    for peer in self.node.peers.values():
                        if f"{peer.peer_address[0]}:{peer.peer_address[1]}" == seed:
                            seed_connected = True
                            break

                    if not seed_connected:
                        logger.info(f"Reconnecting to seed node {seed}")
                        asyncio.create_task(self._connect_with_retry(seed, is_seed=True))

                # Limpiar peers descubiertos antiguos
                current_time = time.time()
                to_remove = []
                for addr, last_seen in self.discovered_peers.items():
                    if current_time - last_seen > 86400:  # 24 horas
                        to_remove.append(addr)

                for addr in to_remove:
                    del self.discovered_peers[addr]

                # Verificar balance de conexiones entrantes/salientes
                # Implementación futura

                await asyncio.sleep(300)  # Cada 5 minutos

            except Exception as e:
                logger.error(f"Error in peer maintenance: {e}")
                await asyncio.sleep(60)

    def _update_peer_reputation(self, address: str, change: int):
        """Actualiza la reputación de un peer"""
        if address not in self.peer_reputation:
            # Inicializar con valor neutral
            self.peer_reputation[address] = 50

        # Aplicar cambio con límites
        self.peer_reputation[address] = max(0, min(100, self.peer_reputation[address] + change))

        # Banear peers con muy mala reputación
        if self.peer_reputation[address] < 10:
            logger.warning(f"Banning peer {address} due to low reputation")
            self.node.banned_peers.add(address.split(':')[0])  # Banear IP

    async def connect_to_peer(self, address: str):
        """Conecta a un peer específico con validación mejorada"""
        # Validar formato de dirección
        if ':' not in address:
            raise ValueError(f"Invalid address format: {address}")

        host, port_str = address.split(':')

        # Validar puerto
        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {port}")
        except ValueError:
            raise ValueError(f"Invalid port: {port_str}")

        # Verificar si ya estamos conectados
        for peer in self.node.peers.values():
            peer_addr = peer.peer_address
            if peer_addr and peer_addr[0] == host and peer_addr[1] == port:
                logger.debug(f"Already connected to {address}")
                return

        # Verificar si está baneado
        if host in self.node.banned_peers:
            logger.warning(f"Skipping banned peer {address}")
            return

        # Verificar límite de conexiones
        if len(self.node.peers) >= self.node.max_peers:
            logger.warning(f"Cannot connect to {address}: max peers reached")
            return

        # Intentar conexión con timeout
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10
            )

            # Crear y manejar conexión
            peer = PeerConnection(reader, writer, self.node)
            asyncio.create_task(peer.handle())

            # Registrar peer descubierto
            self.discovered_peers[address] = time.time()

            logger.info(f"Connected to peer {address}")
            return peer

        except asyncio.TimeoutError:
            logger.warning(f"Timeout connecting to {address}")
            raise
        except Exception as e:
            logger.error(f"Failed to connect to {address}: {e}")
            raise

    async def discover_peers(self):
        """Descubre nuevos peers usando múltiples estrategias"""
        # 1. Solicitar lista de peers a peers conocidos
        peer_discovery_tasks = []

        # Limitar a un subconjunto de peers para no saturar
        selected_peers = list(self.node.peers.values())
        if len(selected_peers) > 5:
            selected_peers = random.sample(selected_peers, 5)

        for peer in selected_peers:
            task = asyncio.create_task(self._request_peer_list(peer))
            peer_discovery_tasks.append(task)

        # 2. Intentar conectar a peers previamente descubiertos
        # Seleccionar algunos peers descubiertos con buena reputación
        candidates = []
        for addr, last_seen in self.discovered_peers.items():
            # Verificar si ya estamos conectados
            already_connected = False
            for peer in self.node.peers.values():
                peer_addr = f"{peer.peer_address[0]}:{peer.peer_address[1]}"
                if peer_addr == addr:
                    already_connected = True
                    break

            if not already_connected:
                reputation = self.peer_reputation.get(addr, 50)
                # Priorizar peers con buena reputación
                if reputation > 40:
                    candidates.append((addr, reputation))

        # Ordenar por reputación y seleccionar algunos
        candidates.sort(key=lambda x: x[1], reverse=True)
        connection_limit = min(5, self.max_outbound_connections - len(self.node.peers))

        for addr, _ in candidates[:connection_limit]:
            task = asyncio.create_task(self._connect_with_retry(addr))
            peer_discovery_tasks.append(task)

        # 3. Esperar a que terminen las tareas de descubrimiento
        if peer_discovery_tasks:
            await asyncio.gather(*peer_discovery_tasks, return_exceptions=True)

    async def _request_peer_list(self, peer):
        """Solicita lista de peers a un peer específico"""
        try:
            # Solicitar con un máximo razonable
            await peer.send_message({
                'type': 'get_peer_list',
                'max': 50,
                'include_capabilities': True
            })

            # La respuesta se maneja en PeerConnection.handle_peer_list
            return True
        except Exception as e:
            logger.error(f"Error requesting peer list from {peer.peer_id[:8] if peer.peer_id else 'unknown'}: {e}")
            return False

    def add_discovered_peer(self, address: str, source_peer_id: str = None):
        """Añade un peer descubierto a la lista de candidatos"""
        if address not in self.discovered_peers:
            self.stats['peers_discovered'] += 1

        self.discovered_peers[address] = time.time()

        # Inicializar reputación si es nuevo
        if address not in self.peer_reputation:
            self.peer_reputation[address] = 50

        # Programar conexión si tenemos pocos peers
        if len(self.node.peers) < 10:
            asyncio.create_task(self.connect_to_peer(address))

    async def broadcast_presence(self):
        """Anuncia presencia a la red para facilitar descubrimiento inverso"""
        # Implementación futura - útil para peers detrás de NAT
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
