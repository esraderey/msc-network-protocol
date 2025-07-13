#!/usr/bin/env python3
"""
MSC Wallet v3.0 - Enterprise-Grade Cryptocurrency Wallet
Compatible con MSC Blockchain v3.0
Incluye HD wallet, multi-signature, hardware wallet support y más
"""

import os
import json
import time
import secrets
import hashlib
import base64
import qrcode
import io
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum, auto
from decimal import Decimal, getcontext
import logging
from pathlib import Path

# Cryptography
import ecdsa
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import ed25519

# BIP32/39/44 for HD wallets
from mnemonic import Mnemonic
import bip32
from eth_account import Account
from eth_utils import keccak, to_checksum_address
from web3 import Web3

# For hardware wallet support
try:
    from ledgerblue.comm import getDongle
    from ledgerblue.commException import CommException
    LEDGER_AVAILABLE = True
except ImportError:
    LEDGER_AVAILABLE = False

try:
    from trezorlib.client import TrezorClient
    from trezorlib.transport import get_transport
    TREZOR_AVAILABLE = True
except ImportError:
    TREZOR_AVAILABLE = False

# Set decimal precision
getcontext().prec = 28

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === CONSTANTS ===
class WalletConstants:
    """Wallet configuration constants"""
    # Network
    MAINNET_CHAIN_ID = 1337
    TESTNET_CHAIN_ID = 13370
    
    # Derivation paths
    ETH_DERIVATION_PATH = "m/44'/60'/0'/0"
    MSC_DERIVATION_PATH = "m/44'/1337'/0'/0"  # Custom for MSC
    
    # Address prefixes
    MSC_ADDRESS_PREFIX = "MSC"
    
    # Security
    PBKDF2_ITERATIONS = 100_000
    SALT_LENGTH = 32
    
    # Transaction
    DEFAULT_GAS_LIMIT = 21_000
    DEFAULT_GAS_PRICE = 20_000_000_000  # 20 Gwei
    
    # File paths
    KEYSTORE_DIR = Path.home() / ".msc_wallet" / "keystore"
    
# === ENUMS ===
class WalletType(Enum):
    """Types of wallets supported"""
    STANDARD = "standard"
    HD = "hierarchical_deterministic"
    MULTISIG = "multisignature"
    HARDWARE = "hardware"
    WATCH_ONLY = "watch_only"

class TransactionStatus(Enum):
    """Transaction status"""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    DROPPED = "dropped"

class TokenStandard(Enum):
    """Token standards"""
    NATIVE = "native"
    ERC20 = "erc20"
    ERC721 = "erc721"
    ERC1155 = "erc1155"

# === DATA STRUCTURES ===
@dataclass
class AccountInfo:
    """Account information"""
    address: str
    public_key: str
    derivation_path: Optional[str] = None
    index: Optional[int] = None
    label: Optional[str] = None
    created_at: float = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()

@dataclass
class TokenBalance:
    """Token balance information"""
    contract_address: str
    symbol: str
    name: str
    decimals: int
    balance: Decimal
    standard: TokenStandard
    logo_url: Optional[str] = None
    price_usd: Optional[Decimal] = None

@dataclass
class TransactionData:
    """Transaction data structure"""
    from_address: str
    to_address: str
    value: Decimal
    gas_limit: int = WalletConstants.DEFAULT_GAS_LIMIT
    gas_price: int = WalletConstants.DEFAULT_GAS_PRICE
    nonce: Optional[int] = None
    data: bytes = b""
    chain_id: int = WalletConstants.MAINNET_CHAIN_ID
    
@dataclass
class SignedTransaction:
    """Signed transaction"""
    raw_transaction: bytes
    transaction_hash: str
    transaction_data: TransactionData
    signature: Dict[str, Any]

# === HD WALLET ===
class HDWallet:
    """Hierarchical Deterministic Wallet (BIP32/39/44)"""
    
    def __init__(self, mnemonic: Optional[str] = None, passphrase: str = "", 
                 language: str = "english"):
        self.mnemo = Mnemonic(language)
        
        if mnemonic:
            if not self.mnemo.check(mnemonic):
                raise ValueError("Invalid mnemonic phrase")
            self.mnemonic = mnemonic
        else:
            # Generate new mnemonic (256 bits = 24 words)
            self.mnemonic = self.mnemo.generate(strength=256)
        
        # Generate seed from mnemonic
        self.seed = self.mnemo.to_seed(self.mnemonic, passphrase)
        
        # Create master key
        self.master_key = bip32.HDPrivateKey.from_seed(self.seed)
        
        # Cache for derived accounts
        self._accounts_cache: Dict[str, AccountInfo] = {}
        
    def get_account(self, index: int = 0, derivation_path: Optional[str] = None) -> AccountInfo:
        """Get account at specific index or derivation path"""
        if derivation_path is None:
            derivation_path = f"{WalletConstants.MSC_DERIVATION_PATH}/{index}"
        
        cache_key = f"{derivation_path}:{index}"
        if cache_key in self._accounts_cache:
            return self._accounts_cache[cache_key]
        
        # Derive private key
        derived_key = self.master_key
        for component in derivation_path.split('/')[1:]:  # Skip 'm'
            if component.endswith("'"):
                index_val = int(component[:-1]) + 0x80000000
            else:
                index_val = int(component)
            derived_key = derived_key.child_key(index_val)
        
        # Get keys
        private_key_bytes = derived_key.private_key.to_bytes()
        private_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        public_key = private_key.get_verifying_key()
        
        # Generate MSC address
        address = self._generate_msc_address(public_key)
        
        account = AccountInfo(
            address=address,
            public_key=public_key.to_string().hex(),
            derivation_path=derivation_path,
            index=index
        )
        
        self._accounts_cache[cache_key] = account
        return account
    
    def _generate_msc_address(self, public_key: VerifyingKey) -> str:
        """Generate MSC address from public key"""
        # Get uncompressed public key
        pub_key_bytes = public_key.to_string()
        
        # MSC uses modified Ethereum-style addresses with custom prefix
        # Keccak256 hash of public key
        keccak_hash = keccak(pub_key_bytes)
        
        # Take last 20 bytes
        address_bytes = keccak_hash[-20:]
        
        # Convert to checksum address
        eth_address = to_checksum_address(address_bytes)
        
        # Add MSC prefix
        return f"MSC{eth_address[2:]}"  # Remove '0x' and add 'MSC'
    
    def get_private_key(self, index: int = 0, derivation_path: Optional[str] = None) -> SigningKey:
        """Get private key for account"""
        if derivation_path is None:
            derivation_path = f"{WalletConstants.MSC_DERIVATION_PATH}/{index}"
        
        # Derive private key
        derived_key = self.master_key
        for component in derivation_path.split('/')[1:]:
            if component.endswith("'"):
                index_val = int(component[:-1]) + 0x80000000
            else:
                index_val = int(component)
            derived_key = derived_key.child_key(index_val)
        
        private_key_bytes = derived_key.private_key.to_bytes()
        return SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    
    def generate_addresses(self, count: int = 10, start_index: int = 0) -> List[AccountInfo]:
        """Generate multiple addresses"""
        accounts = []
        for i in range(start_index, start_index + count):
            account = self.get_account(i)
            accounts.append(account)
        return accounts
    
    def export_mnemonic(self) -> str:
        """Export mnemonic phrase"""
        return self.mnemonic
    
    def export_seed(self) -> bytes:
        """Export seed (DANGEROUS - handle with care)"""
        return self.seed

# === MULTI-SIGNATURE WALLET ===
class MultiSigWallet:
    """Multi-signature wallet implementation"""
    
    def __init__(self, threshold: int, owners: List[str], wallet_address: Optional[str] = None):
        if threshold > len(owners):
            raise ValueError("Threshold cannot be greater than number of owners")
        if threshold < 1:
            raise ValueError("Threshold must be at least 1")
        
        self.threshold = threshold
        self.owners = sorted(owners)  # Sort for deterministic address
        self.wallet_address = wallet_address or self._compute_wallet_address()
        self.pending_transactions: Dict[str, MultiSigTransaction] = {}
        
    def _compute_wallet_address(self) -> str:
        """Compute deterministic multisig wallet address"""
        data = f"{self.threshold}:{''.join(self.owners)}"
        address_hash = hashlib.sha256(data.encode()).hexdigest()
        return f"MSC_MULTISIG_{address_hash[:32]}"
    
    def create_transaction(self, tx_data: TransactionData) -> 'MultiSigTransaction':
        """Create a new multisig transaction"""
        tx_id = hashlib.sha256(
            f"{tx_data.to_address}{tx_data.value}{time.time()}".encode()
        ).hexdigest()
        
        multisig_tx = MultiSigTransaction(
            tx_id=tx_id,
            tx_data=tx_data,
            threshold=self.threshold,
            owners=self.owners
        )
        
        self.pending_transactions[tx_id] = multisig_tx
        return multisig_tx
    
    def sign_transaction(self, tx_id: str, owner_address: str, signature: str) -> bool:
        """Add signature to transaction"""
        if tx_id not in self.pending_transactions:
            raise ValueError("Transaction not found")
        
        if owner_address not in self.owners:
            raise ValueError("Not an owner")
        
        tx = self.pending_transactions[tx_id]
        tx.add_signature(owner_address, signature)
        
        if tx.is_ready():
            # Transaction has enough signatures
            return True
        
        return False
    
    def get_pending_transactions(self) -> List['MultiSigTransaction']:
        """Get all pending transactions"""
        return list(self.pending_transactions.values())

@dataclass
class MultiSigTransaction:
    """Multi-signature transaction"""
    tx_id: str
    tx_data: TransactionData
    threshold: int
    owners: List[str]
    signatures: Dict[str, str] = None
    created_at: float = None
    
    def __post_init__(self):
        if self.signatures is None:
            self.signatures = {}
        if self.created_at is None:
            self.created_at = time.time()
    
    def add_signature(self, owner: str, signature: str):
        """Add signature from owner"""
        if owner not in self.owners:
            raise ValueError("Not an owner")
        self.signatures[owner] = signature
    
    def is_ready(self) -> bool:
        """Check if transaction has enough signatures"""
        return len(self.signatures) >= self.threshold
    
    def get_missing_signatures(self) -> List[str]:
        """Get list of owners who haven't signed"""
        return [owner for owner in self.owners if owner not in self.signatures]

# === KEYSTORE ===
class Keystore:
    """Secure key storage with encryption"""
    
    def __init__(self, keystore_dir: Optional[Path] = None):
        self.keystore_dir = keystore_dir or WalletConstants.KEYSTORE_DIR
        self.keystore_dir.mkdir(parents=True, exist_ok=True)
    
    def encrypt_key(self, private_key: Union[bytes, SigningKey], password: str) -> Dict[str, Any]:
        """Encrypt private key with password"""
        if isinstance(private_key, SigningKey):
            private_key = private_key.to_string()
        
        # Generate salt
        salt = os.urandom(WalletConstants.SALT_LENGTH)
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=WalletConstants.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Encrypt private key
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(private_key) + encryptor.finalize()
        
        # Create keystore object
        keystore = {
            "version": 3,
            "id": str(secrets.token_hex(16)),
            "address": self._get_address_from_private_key(private_key),
            "crypto": {
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "cipherparams": {
                    "iv": base64.b64encode(iv).decode()
                },
                "cipher": "aes-128-ctr",
                "kdf": "pbkdf2",
                "kdfparams": {
                    "dklen": 32,
                    "salt": base64.b64encode(salt).decode(),
                    "c": WalletConstants.PBKDF2_ITERATIONS,
                    "prf": "hmac-sha256"
                }
            }
        }
        
        return keystore
    
    def decrypt_key(self, keystore: Dict[str, Any], password: str) -> SigningKey:
        """Decrypt private key from keystore"""
        crypto = keystore["crypto"]
        
        # Decode parameters
        salt = base64.b64decode(crypto["kdfparams"]["salt"])
        iv = base64.b64decode(crypto["cipherparams"]["iv"])
        ciphertext = base64.b64decode(crypto["ciphertext"])
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=crypto["kdfparams"]["dklen"],
            salt=salt,
            iterations=crypto["kdfparams"]["c"],
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        private_key_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        return SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    
    def save_keystore(self, keystore: Dict[str, Any], filename: Optional[str] = None) -> str:
        """Save keystore to file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"UTC--{timestamp}--{keystore['address']}"
        
        filepath = self.keystore_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(keystore, f, indent=2)
        
        logger.info(f"Keystore saved to {filepath}")
        return str(filepath)
    
    def load_keystore(self, filename: str) -> Dict[str, Any]:
        """Load keystore from file"""
        filepath = self.keystore_dir / filename
        
        with open(filepath, 'r') as f:
            keystore = json.load(f)
        
        return keystore
    
    def list_keystores(self) -> List[Dict[str, str]]:
        """List all keystores"""
        keystores = []
        
        for filepath in self.keystore_dir.glob("UTC--*"):
            try:
                with open(filepath, 'r') as f:
                    keystore = json.load(f)
                    keystores.append({
                        "filename": filepath.name,
                        "address": keystore["address"],
                        "created": filepath.name.split("--")[1]
                    })
            except Exception as e:
                logger.error(f"Error reading keystore {filepath}: {e}")
        
        return keystores
    
    def _get_address_from_private_key(self, private_key: bytes) -> str:
        """Get address from private key"""
        signing_key = SigningKey.from_string(private_key, curve=SECP256k1)
        public_key = signing_key.get_verifying_key()
        
        # Generate MSC address
        pub_key_bytes = public_key.to_string()
        keccak_hash = keccak(pub_key_bytes)
        address_bytes = keccak_hash[-20:]
        eth_address = to_checksum_address(address_bytes)
        
        return f"MSC{eth_address[2:]}"

# === MAIN WALLET CLASS ===
class MSCWallet:
    """Main MSC Wallet class integrating all features"""
    
    def __init__(self, wallet_type: WalletType = WalletType.HD):
        self.wallet_type = wallet_type
        self.keystore = Keystore()
        self.accounts: Dict[str, AccountInfo] = {}
        self.tokens: Dict[str, TokenBalance] = {}
        self.transaction_history: List[SignedTransaction] = []
        
        # Initialize based on wallet type
        if wallet_type == WalletType.HD:
            self.hd_wallet = None
        elif wallet_type == WalletType.MULTISIG:
            self.multisig_wallet = None
        
        # Web3 connection
        self.w3 = None
        self.rpc_url = None
        
    def create_wallet(self, password: str, mnemonic: Optional[str] = None) -> Dict[str, Any]:
        """Create new wallet"""
        if self.wallet_type == WalletType.HD:
            # Create HD wallet
            self.hd_wallet = HDWallet(mnemonic)
            
            # Get first account
            account = self.hd_wallet.get_account(0)
            self.accounts[account.address] = account
            
            # Encrypt and save master key
            master_private_key = self.hd_wallet.master_key.private_key.to_bytes()
            keystore = self.keystore.encrypt_key(master_private_key, password)
            keystore_path = self.keystore.save_keystore(keystore)
            
            return {
                "mnemonic": self.hd_wallet.mnemonic,
                "address": account.address,
                "keystore_path": keystore_path
            }
            
        elif self.wallet_type == WalletType.STANDARD:
            # Create standard wallet
            private_key = SigningKey.generate(curve=SECP256k1)
            public_key = private_key.get_verifying_key()
            
            # Generate address
            address = self._generate_address(public_key)
            
            account = AccountInfo(
                address=address,
                public_key=public_key.to_string().hex()
            )
            self.accounts[address] = account
            
            # Encrypt and save
            keystore = self.keystore.encrypt_key(private_key, password)
            keystore_path = self.keystore.save_keystore(keystore)
            
            return {
                "address": address,
                "keystore_path": keystore_path
            }
    
    def import_wallet(self, keystore_path: str, password: str) -> AccountInfo:
        """Import wallet from keystore"""
        # Load keystore
        with open(keystore_path, 'r') as f:
            keystore = json.load(f)
        
        # Decrypt private key
        private_key = self.keystore.decrypt_key(keystore, password)
        public_key = private_key.get_verifying_key()
        
        # Create account info
        account = AccountInfo(
            address=keystore["address"],
            public_key=public_key.to_string().hex()
        )
        
        self.accounts[account.address] = account
        return account
    
    def import_mnemonic(self, mnemonic: str, password: str, passphrase: str = "") -> Dict[str, Any]:
        """Import wallet from mnemonic"""
        if self.wallet_type != WalletType.HD:
            raise ValueError("Mnemonic import only supported for HD wallets")
        
        self.hd_wallet = HDWallet(mnemonic, passphrase)
        
        # Get first account
        account = self.hd_wallet.get_account(0)
        self.accounts[account.address] = account
        
        # Encrypt and save
        master_private_key = self.hd_wallet.master_key.private_key.to_bytes()
        keystore = self.keystore.encrypt_key(master_private_key, password)
        keystore_path = self.keystore.save_keystore(keystore)
        
        return {
            "address": account.address,
            "keystore_path": keystore_path
        }
    
    def connect_to_network(self, rpc_url: str):
        """Connect to MSC network"""
        self.rpc_url = rpc_url
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        if not self.w3.isConnected():
            raise ConnectionError("Failed to connect to network")
        
        logger.info(f"Connected to network at {rpc_url}")
    
    def get_balance(self, address: Optional[str] = None) -> Decimal:
        """Get balance for address"""
        if not self.w3:
            raise ConnectionError("Not connected to network")
        
        if address is None:
            if not self.accounts:
                raise ValueError("No accounts available")
            address = list(self.accounts.keys())[0]
        
        # Convert MSC address to Ethereum format for Web3
        eth_address = self._msc_to_eth_address(address)
        
        balance_wei = self.w3.eth.get_balance(eth_address)
        balance = Decimal(balance_wei) / Decimal(10**18)
        
        return balance
    
    def get_token_balance(self, token_address: str, address: Optional[str] = None) -> Decimal:
        """Get token balance"""
        if not self.w3:
            raise ConnectionError("Not connected to network")
        
        if address is None:
            address = list(self.accounts.keys())[0]
        
        # ERC20 ABI for balanceOf
        erc20_abi = [{
            "constant": True,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
            "type": "function"
        }]
        
        # Get contract
        contract = self.w3.eth.contract(
            address=Web3.toChecksumAddress(token_address),
            abi=erc20_abi
        )
        
        # Get balance
        eth_address = self._msc_to_eth_address(address)
        balance = contract.functions.balanceOf(eth_address).call()
        
        return Decimal(balance)
    
    def create_transaction(self, to_address: str, amount: Decimal, 
                          from_address: Optional[str] = None,
                          gas_price: Optional[int] = None,
                          gas_limit: Optional[int] = None) -> TransactionData:
        """Create transaction"""
        if from_address is None:
            from_address = list(self.accounts.keys())[0]
        
        if gas_price is None:
            gas_price = self._estimate_gas_price()
        
        if gas_limit is None:
            gas_limit = WalletConstants.DEFAULT_GAS_LIMIT
        
        # Get nonce
        nonce = self._get_nonce(from_address)
        
        # Convert amount to wei
        value_wei = int(amount * Decimal(10**18))
        
        tx_data = TransactionData(
            from_address=from_address,
            to_address=to_address,
            value=Decimal(value_wei),
            gas_price=gas_price,
            gas_limit=gas_limit,
            nonce=nonce,
            chain_id=self.w3.eth.chain_id if self.w3 else WalletConstants.MAINNET_CHAIN_ID
        )
        
        return tx_data
    
    def sign_transaction(self, tx_data: TransactionData, private_key: Optional[SigningKey] = None) -> SignedTransaction:
        """Sign transaction"""
        if private_key is None:
            # Get private key for from_address
            if self.hd_wallet:
                # Find account index
                for address, account in self.accounts.items():
                    if address == tx_data.from_address:
                        private_key = self.hd_wallet.get_private_key(account.index or 0)
                        break
            else:
                raise ValueError("Private key required for signing")
        
        # Create transaction dict for Web3
        tx_dict = {
            'nonce': tx_data.nonce,
            'gasPrice': tx_data.gas_price,
            'gas': tx_data.gas_limit,
            'to': self._msc_to_eth_address(tx_data.to_address),
            'value': int(tx_data.value),
            'data': tx_data.data,
            'chainId': tx_data.chain_id
        }
        
        # Sign with Web3
        account = Account.from_key(private_key.to_string())
        signed_tx = account.sign_transaction(tx_dict)
        
        return SignedTransaction(
            raw_transaction=signed_tx.rawTransaction,
            transaction_hash=signed_tx.hash.hex(),
            transaction_data=tx_data,
            signature={
                'r': hex(signed_tx.r),
                's': hex(signed_tx.s),
                'v': signed_tx.v
            }
        )
    
    def send_transaction(self, signed_tx: SignedTransaction) -> str:
        """Send signed transaction to network"""
        if not self.w3:
            raise ConnectionError("Not connected to network")
        
        # Send transaction
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        # Add to history
        self.transaction_history.append(signed_tx)
        
        logger.info(f"Transaction sent: {tx_hash.hex()}")
        return tx_hash.hex()
    
    def generate_qr_code(self, data: str) -> io.BytesIO:
        """Generate QR code for address or payment request"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        img_bytes.seek(0)
        
        return img_bytes
    
    def create_payment_request(self, amount: Decimal, address: Optional[str] = None, 
                             message: Optional[str] = None) -> str:
        """Create payment request URI"""
        if address is None:
            address = list(self.accounts.keys())[0]
        
        # MSC payment URI format
        uri = f"msc:{address}?amount={amount}"
        
        if message:
            uri += f"&message={message}"
        
        return uri
    
    def backup_wallet(self, password: str, backup_path: Path) -> Dict[str, Any]:
        """Create encrypted backup of wallet"""
        backup_data = {
            "version": "3.0",
            "wallet_type": self.wallet_type.value,
            "accounts": {},
            "timestamp": time.time()
        }
        
        # Add accounts
        for address, account in self.accounts.items():
            backup_data["accounts"][address] = asdict(account)
        
        # Add mnemonic if HD wallet
        if self.hd_wallet:
            backup_data["mnemonic"] = self.hd_wallet.mnemonic
        
        # Encrypt backup
        backup_json = json.dumps(backup_data)
        
        # Derive encryption key
        salt = os.urandom(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=WalletConstants.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Encrypt
        f = Fernet(key)
        encrypted_backup = f.encrypt(backup_json.encode())
        
        # Save
        backup_file = backup_path / f"msc_wallet_backup_{int(time.time())}.bak"
        with open(backup_file, 'wb') as file:
            file.write(salt + encrypted_backup)
        
        logger.info(f"Wallet backed up to {backup_file}")
        
        return {
            "backup_path": str(backup_file),
            "checksum": hashlib.sha256(encrypted_backup).hexdigest()
        }
    
    def restore_from_backup(self, backup_path: Path, password: str):
        """Restore wallet from backup"""
        with open(backup_path, 'rb') as file:
            data = file.read()
        
        # Extract salt and encrypted data
        salt = data[:32]
        encrypted_backup = data[32:]
        
        # Derive decryption key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=WalletConstants.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Decrypt
        f = Fernet(key)
        backup_json = f.decrypt(encrypted_backup).decode()
        backup_data = json.loads(backup_json)
        
        # Restore wallet
        self.wallet_type = WalletType(backup_data["wallet_type"])
        
        # Restore accounts
        for address, account_data in backup_data["accounts"].items():
            self.accounts[address] = AccountInfo(**account_data)
        
        # Restore HD wallet if present
        if "mnemonic" in backup_data:
            self.hd_wallet = HDWallet(backup_data["mnemonic"])
        
        logger.info("Wallet restored from backup")
    
    def export_private_key(self, address: str, password: str) -> str:
        """Export private key for address (DANGEROUS)"""
        logger.warning("Exporting private key - handle with extreme care!")
        
        # This would require the password to decrypt the keystore
        # Implementation depends on how keys are stored
        
        # For HD wallet
        if self.hd_wallet and address in self.accounts:
            account = self.accounts[address]
            private_key = self.hd_wallet.get_private_key(account.index or 0)
            return private_key.to_string().hex()
        
        raise NotImplementedError("Private key export not implemented for this wallet type")
    
    def _generate_address(self, public_key: VerifyingKey) -> str:
        """Generate MSC address from public key"""
        pub_key_bytes = public_key.to_string()
        keccak_hash = keccak(pub_key_bytes)
        address_bytes = keccak_hash[-20:]
        eth_address = to_checksum_address(address_bytes)
        return f"MSC{eth_address[2:]}"
    
    def _msc_to_eth_address(self, msc_address: str) -> str:
        """Convert MSC address to Ethereum format"""
        if msc_address.startswith("MSC"):
            return "0x" + msc_address[3:]
        return msc_address
    
    def _estimate_gas_price(self) -> int:
        """Estimate current gas price"""
        if self.w3:
            return self.w3.eth.gas_price
        return WalletConstants.DEFAULT_GAS_PRICE
    
    def _get_nonce(self, address: str) -> int:
        """Get nonce for address"""
        if self.w3:
            eth_address = self._msc_to_eth_address(address)
            return self.w3.eth.get_transaction_count(eth_address)
        return 0

# === HARDWARE WALLET SUPPORT ===
class HardwareWallet:
    """Base class for hardware wallet support"""
    
    def __init__(self, device_type: str):
        self.device_type = device_type
        self.connected = False
    
    def connect(self):
        """Connect to hardware wallet"""
        raise NotImplementedError
    
    def get_address(self, derivation_path: str) -> str:
        """Get address from hardware wallet"""
        raise NotImplementedError
    
    def sign_transaction(self, tx_data: TransactionData, derivation_path: str) -> SignedTransaction:
        """Sign transaction with hardware wallet"""
        raise NotImplementedError

class LedgerWallet(HardwareWallet):
    """Ledger hardware wallet support"""
    
    def __init__(self):
        super().__init__("Ledger")
        self.dongle = None
    
    def connect(self):
        """Connect to Ledger device"""
        if not LEDGER_AVAILABLE:
            raise ImportError("Ledger libraries not installed")
        
        try:
            self.dongle = getDongle(True)
            self.connected = True
            logger.info("Connected to Ledger device")
        except CommException as e:
            raise ConnectionError(f"Failed to connect to Ledger: {e}")
    
    def get_address(self, derivation_path: str = WalletConstants.MSC_DERIVATION_PATH) -> str:
        """Get address from Ledger"""
        if not self.connected:
            self.connect()
        
        # Ledger APDU commands would go here
        # This is a simplified implementation
        raise NotImplementedError("Ledger integration requires custom app")

class TrezorWallet(HardwareWallet):
    """Trezor hardware wallet support"""
    
    def __init__(self):
        super().__init__("Trezor")
        self.client = None
    
    def connect(self):
        """Connect to Trezor device"""
        if not TREZOR_AVAILABLE:
            raise ImportError("Trezor libraries not installed")
        
        try:
            transport = get_transport()
            self.client = TrezorClient(transport)
            self.connected = True
            logger.info("Connected to Trezor device")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to Trezor: {e}")

# === WALLET MANAGER ===
class WalletManager:
    """Manage multiple wallets"""
    
    def __init__(self):
        self.wallets: Dict[str, MSCWallet] = {}
        self.active_wallet_id: Optional[str] = None
    
    def create_wallet(self, wallet_id: str, wallet_type: WalletType = WalletType.HD, 
                     password: str = "") -> MSCWallet:
        """Create new managed wallet"""
        if wallet_id in self.wallets:
            raise ValueError(f"Wallet {wallet_id} already exists")
        
        wallet = MSCWallet(wallet_type)
        wallet.create_wallet(password)
        
        self.wallets[wallet_id] = wallet
        
        if self.active_wallet_id is None:
            self.active_wallet_id = wallet_id
        
        return wallet
    
    def import_wallet(self, wallet_id: str, keystore_path: str, password: str) -> MSCWallet:
        """Import wallet into manager"""
        if wallet_id in self.wallets:
            raise ValueError(f"Wallet {wallet_id} already exists")
        
        wallet = MSCWallet()
        wallet.import_wallet(keystore_path, password)
        
        self.wallets[wallet_id] = wallet
        return wallet
    
    def get_wallet(self, wallet_id: Optional[str] = None) -> MSCWallet:
        """Get wallet by ID or active wallet"""
        if wallet_id is None:
            wallet_id = self.active_wallet_id
        
        if wallet_id not in self.wallets:
            raise ValueError(f"Wallet {wallet_id} not found")
        
        return self.wallets[wallet_id]
    
    def set_active_wallet(self, wallet_id: str):
        """Set active wallet"""
        if wallet_id not in self.wallets:
            raise ValueError(f"Wallet {wallet_id} not found")
        
        self.active_wallet_id = wallet_id
    
    def list_wallets(self) -> List[Dict[str, Any]]:
        """List all wallets"""
        wallets = []
        
        for wallet_id, wallet in self.wallets.items():
            wallet_info = {
                "id": wallet_id,
                "type": wallet.wallet_type.value,
                "accounts": len(wallet.accounts),
                "active": wallet_id == self.active_wallet_id
            }
            
            if wallet.accounts:
                wallet_info["primary_address"] = list(wallet.accounts.keys())[0]
            
            wallets.append(wallet_info)
        
        return wallets

# === CLI INTERFACE ===
def create_cli():
    """Create command-line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='MSC Wallet v3.0 - Enterprise Crypto Wallet',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Create wallet
    create_parser = subparsers.add_parser('create', help='Create new wallet')
    create_parser.add_argument('--type', choices=['standard', 'hd', 'multisig'], 
                             default='hd', help='Wallet type')
    create_parser.add_argument('--password', required=True, help='Wallet password')
    create_parser.add_argument('--mnemonic', help='Import from mnemonic')
    
    # Import wallet
    import_parser = subparsers.add_parser('import', help='Import wallet')
    import_parser.add_argument('--keystore', help='Keystore file path')
    import_parser.add_argument('--mnemonic', help='Mnemonic phrase')
    import_parser.add_argument('--password', required=True, help='Wallet password')
    
    # Show address
    address_parser = subparsers.add_parser('address', help='Show wallet address')
    address_parser.add_argument('--index', type=int, default=0, help='Account index for HD wallet')
    address_parser.add_argument('--qr', action='store_true', help='Generate QR code')
    
    # Get balance
    balance_parser = subparsers.add_parser('balance', help='Get balance')
    balance_parser.add_argument('--address', help='Address to check')
    balance_parser.add_argument('--rpc', default='http://localhost:8545', help='RPC URL')
    
    # Send transaction
    send_parser = subparsers.add_parser('send', help='Send transaction')
    send_parser.add_argument('--to', required=True, help='Recipient address')
    send_parser.add_argument('--amount', required=True, type=float, help='Amount in MSC')
    send_parser.add_argument('--from', dest='from_addr', help='From address')
    send_parser.add_argument('--password', required=True, help='Wallet password')
    send_parser.add_argument('--rpc', default='http://localhost:8545', help='RPC URL')
    
    # Backup wallet
    backup_parser = subparsers.add_parser('backup', help='Backup wallet')
    backup_parser.add_argument('--password', required=True, help='Backup password')
    backup_parser.add_argument('--path', default='.', help='Backup directory')
    
    # List accounts
    list_parser = subparsers.add_parser('list', help='List accounts')
    list_parser.add_argument('--show-balance', action='store_true', help='Show balances')
    
    return parser

# === MAIN FUNCTION ===
def main():
    """Main entry point"""
    parser = create_cli()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize wallet manager
    manager = WalletManager()
    
    try:
        if args.command == 'create':
            # Create wallet
            wallet_type = WalletType[args.type.upper()]
            wallet = MSCWallet(wallet_type)
            
            if args.mnemonic:
                result = wallet.import_mnemonic(args.mnemonic, args.password)
            else:
                result = wallet.create_wallet(args.password)
            
            print("\n✅ Wallet created successfully!")
            print(f"Address: {result['address']}")
            
            if 'mnemonic' in result:
                print(f"\n🔐 IMPORTANT - Save your recovery phrase:")
                print(f"{result['mnemonic']}")
                print("\n⚠️  Never share this phrase with anyone!")
            
            if 'keystore_path' in result:
                print(f"\nKeystore saved to: {result['keystore_path']}")
        
        elif args.command == 'import':
            wallet = MSCWallet()
            
            if args.keystore:
                account = wallet.import_wallet(args.keystore, args.password)
                print(f"\n✅ Wallet imported successfully!")
                print(f"Address: {account.address}")
            
            elif args.mnemonic:
                result = wallet.import_mnemonic(args.mnemonic, args.password)
                print(f"\n✅ HD Wallet imported successfully!")
                print(f"Address: {result['address']}")
        
        elif args.command == 'address':
            # Would need to load wallet first
            print("Address display functionality - implement wallet loading")
        
        elif args.command == 'balance':
            wallet = MSCWallet()
            wallet.connect_to_network(args.rpc)
            
            if args.address:
                balance = wallet.get_balance(args.address)
            else:
                # Would need to load wallet
                print("Please specify --address")
                return
            
            print(f"\nBalance: {balance:.6f} MSC")
        
        elif args.command == 'send':
            # This would require loading the wallet with the private key
            print("Send functionality - implement wallet loading and signing")
        
        elif args.command == 'backup':
            # Would need to load wallet first
            print("Backup functionality - implement wallet loading")
        
        elif args.command == 'list':
            # Would need to load wallet first
            print("List functionality - implement wallet loading")
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1

if __name__ == "__main__":
    main()