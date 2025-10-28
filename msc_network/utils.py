"""
Utilidades compartidas para MSC Network
"""

import hashlib
import json
from typing import Any, Union

def rlp_encode(data: Any) -> bytes:
    """Codificación RLP simplificada"""
    if isinstance(data, bytes):
        return data
    elif isinstance(data, str):
        return data.encode()
    elif isinstance(data, int):
        return data.to_bytes((data.bit_length() + 7) // 8, 'big')
    elif isinstance(data, list):
        result = b''
        for item in data:
            result += rlp_encode(item)
        return result
    else:
        return str(data).encode()

def rlp_decode(data: bytes) -> Any:
    """Decodificación RLP simplificada"""
    if not data:
        return None
    # Implementación simplificada - en producción usar librería RLP
    return data

def sha3_256(data: bytes) -> bytes:
    """Hash SHA3-256"""
    return hashlib.sha256(data).digest()

def keccak256(data: bytes) -> bytes:
    """Hash Keccak-256 (SHA3-256 con padding diferente)"""
    # Implementación simplificada usando SHA256
    return hashlib.sha256(data).digest()

def to_hex(data: Union[bytes, int, str]) -> str:
    """Convierte datos a formato hexadecimal"""
    if isinstance(data, bytes):
        return '0x' + data.hex()
    elif isinstance(data, int):
        return '0x' + hex(data)[2:]
    elif isinstance(data, str):
        if data.startswith('0x'):
            return data
        else:
            return '0x' + data
    else:
        return '0x' + str(data)

def from_hex(data: str) -> bytes:
    """Convierte string hexadecimal a bytes"""
    if data.startswith('0x'):
        data = data[2:]
    return bytes.fromhex(data)

def to_wei(amount: Union[str, float, int], unit: str = 'ether') -> int:
    """Convierte cantidad a wei"""
    units = {
        'wei': 1,
        'kwei': 10**3,
        'mwei': 10**6,
        'gwei': 10**9,
        'szabo': 10**12,
        'finney': 10**15,
        'ether': 10**18
    }
    
    if unit not in units:
        raise ValueError(f"Unknown unit: {unit}")
    
    multiplier = units[unit]
    return int(float(amount) * multiplier)

def from_wei(amount: int, unit: str = 'ether') -> float:
    """Convierte wei a otra unidad"""
    units = {
        'wei': 1,
        'kwei': 10**3,
        'mwei': 10**6,
        'gwei': 10**9,
        'szabo': 10**12,
        'finney': 10**15,
        'ether': 10**18
    }
    
    if unit not in units:
        raise ValueError(f"Unknown unit: {unit}")
    
    divisor = units[unit]
    return amount / divisor

def generate_address() -> str:
    """Genera una dirección de wallet aleatoria"""
    import secrets
    private_key = secrets.token_bytes(32)
    public_key = hashlib.sha256(private_key).digest()
    address = hashlib.sha256(public_key).digest()[-20:]
    return '0x' + address.hex()

def validate_address(address: str) -> bool:
    """Valida formato de dirección"""
    if not isinstance(address, str):
        return False
    
    if not address.startswith('0x'):
        return False
    
    if len(address) != 42:  # 0x + 40 caracteres hex
        return False
    
    try:
        int(address[2:], 16)
        return True
    except ValueError:
        return False

def calculate_merkle_root(leaves: list) -> str:
    """Calcula Merkle root de una lista de hashes"""
    if not leaves:
        return '0x' + '0' * 64
    
    if len(leaves) == 1:
        return leaves[0]
    
    # Asegurar número par de hojas
    if len(leaves) % 2 == 1:
        leaves.append(leaves[-1])
    
    next_level = []
    for i in range(0, len(leaves), 2):
        combined = leaves[i] + leaves[i + 1]
        next_hash = '0x' + hashlib.sha256(combined.encode()).hexdigest()
        next_level.append(next_hash)
    
    return calculate_merkle_root(next_level)

def format_gas_price(gas_price: int) -> str:
    """Formatea precio de gas en Gwei"""
    gwei = from_wei(gas_price, 'gwei')
    return f"{gwei:.2f} Gwei"

def format_balance(balance: int) -> str:
    """Formatea balance en MSC"""
    msc = from_wei(balance, 'ether')
    return f"{msc:.6f} MSC"

def calculate_gas_cost(gas_used: int, gas_price: int) -> int:
    """Calcula costo total de gas"""
    return gas_used * gas_price

def estimate_transaction_fee(gas_limit: int, gas_price: int) -> int:
    """Estima fee de transacción"""
    return gas_limit * gas_price

def is_contract_address(address: str) -> bool:
    """Verifica si una dirección es de contrato (simplificado)"""
    # En implementación real, consultaría el estado del blockchain
    return address.startswith('0x') and len(address) == 42

def create_transaction_hash(tx_data: dict) -> str:
    """Crea hash de transacción"""
    tx_string = json.dumps(tx_data, sort_keys=True)
    return '0x' + hashlib.sha256(tx_string.encode()).hexdigest()

def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verifica firma digital (simplificado)"""
    # Implementación simplificada - en producción usar criptografía real
    expected_hash = hashlib.sha256(message).digest()
    return signature == expected_hash

def generate_random_bytes(length: int) -> bytes:
    """Genera bytes aleatorios"""
    import secrets
    return secrets.token_bytes(length)

def calculate_difficulty(target_time: int, actual_time: int, current_difficulty: int) -> int:
    """Calcula nueva dificultad basada en tiempo de bloque"""
    if actual_time < target_time:
        # Bloque muy rápido, aumentar dificultad
        return current_difficulty + 1
    elif actual_time > target_time * 2:
        # Bloque muy lento, disminuir dificultad
        return max(1, current_difficulty - 1)
    else:
        # Tiempo normal, mantener dificultad
        return current_difficulty
