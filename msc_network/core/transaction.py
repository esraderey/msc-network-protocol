"""
Clase Transaction del blockchain MSC
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .types import TransactionType
from .config import BlockchainConfig

from ..utils import rlp_encode

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
