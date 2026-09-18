"""Verifiable random output backed by Ed25519 signatures."""

from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..utils import sha3_256


class VRF:
    """A publicly verifiable deterministic random function."""

    def __init__(self, private_key: bytes):
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("VRF private key must contain 32 bytes")
        self.private_key = private_key
        self._signing_key = Ed25519PrivateKey.from_private_bytes(private_key)
        self.public_key = self._signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def generate_proof(self, input_data: bytes) -> tuple:
        proof = self._signing_key.sign(input_data)
        return sha3_256(proof), proof

    @staticmethod
    def verify_proof(input_data: bytes, output: bytes, proof: bytes,
                     public_key: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(proof, input_data)
            return output == sha3_256(proof)
        except (InvalidSignature, ValueError, TypeError):
            return False
