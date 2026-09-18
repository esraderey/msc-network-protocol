"""
Clase Transaction del blockchain MSC
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

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
            'type': self.tx_type.value,
            'v': self.v,
            'r': self.r,
            's': self.s
        }

        tx_string = json.dumps(tx_data, sort_keys=True)
        return '0x' + hashlib.sha256(tx_string.encode()).hexdigest()

    def sign(self, private_key: ec.EllipticCurvePrivateKey):
        """Firma la transacción con ECDSA"""
        message = self.signing_hash()
        signature = private_key.sign(message, ec.ECDSA(Prehashed(hashes.SHA256())))
        r, s = decode_dss_signature(signature)
        self.r = r
        self.s = s

        # EIP-155 includes the recovery id. Determine it from the signer.
        import ecdsa
        raw_signature = ecdsa.util.sigencode_string(r, s, ecdsa.SECP256k1.order)
        public_key = private_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )[1:]
        candidates = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(
            raw_signature, message, ecdsa.SECP256k1
        )
        recovery_id = next(
            (index for index, candidate in enumerate(candidates)
             if candidate.to_string() == public_key),
            None,
        )
        if recovery_id is None:
            raise ValueError("Unable to determine ECDSA recovery id")
        self.v = self.chain_id * 2 + 35 + recovery_id

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
        if self.v is None or self.r is None or self.s is None:
            return None

        try:
            import ecdsa
            def as_int(value):
                if isinstance(value, int):
                    return value
                if isinstance(value, bytes):
                    return int.from_bytes(value, "big")
                if isinstance(value, str):
                    return int(value, 16) if value.startswith("0x") else int(value)
                raise TypeError("Invalid signature component")

            r_int, s_int, v_int = as_int(self.r), as_int(self.s), as_int(self.v)
            recovery_id = v_int - (self.chain_id * 2 + 35)
            if recovery_id < 0 or recovery_id > 3:
                return None
            if not (1 <= r_int < ecdsa.SECP256k1.order and
                    1 <= s_int < ecdsa.SECP256k1.order):
                return None

            signature = ecdsa.util.sigencode_string(
                r_int, s_int, ecdsa.SECP256k1.order
            )
            candidates = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(
                signature, self.signing_hash(), ecdsa.SECP256k1
            )
            if recovery_id >= len(candidates):
                return None
            public_key_bytes = candidates[recovery_id].to_string()
            address_hash = hashlib.sha256(public_key_bytes).digest()
            address = address_hash[-20:]
            return "0x" + address.hex()
        except Exception:
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
        return decode_dss_signature(signature)
