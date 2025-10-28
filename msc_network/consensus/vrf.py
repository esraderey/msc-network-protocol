"""
Verifiable Random Function para selección segura de validadores
"""

from ..utils import sha3_256

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
        hash_result = sha3_256(combined)
        
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
        expected_hash = sha3_256(combined)
        
        return proof_hash == expected_hash
