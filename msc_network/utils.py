"""Utilidades deterministas y primitivas de serialización del protocolo."""

import hashlib
import json
from typing import Any, Union


def rlp_encode(data: Any) -> bytes:
    """Codifica bytes, enteros, cadenas y listas usando RLP canónico."""
    if isinstance(data, int):
        if data < 0:
            raise ValueError("RLP does not encode negative integers")
        data = b"" if data == 0 else data.to_bytes((data.bit_length() + 7) // 8, "big")
    elif isinstance(data, str):
        data = data.encode()

    if isinstance(data, bytes):
        if len(data) == 1 and data[0] < 0x80:
            return data
        if len(data) <= 55:
            return bytes([0x80 + len(data)]) + data
        length = len(data).to_bytes((len(data).bit_length() + 7) // 8, "big")
        return bytes([0xb7 + len(length)]) + length + data

    if isinstance(data, list):
        payload = b"".join(rlp_encode(item) for item in data)
        if len(payload) <= 55:
            return bytes([0xc0 + len(payload)]) + payload
        length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
        return bytes([0xf7 + len(length)]) + length + payload

    raise TypeError(f"Cannot RLP encode type {type(data).__name__}")


def rlp_decode(data: bytes) -> Any:
    """Decodifica un único valor RLP y rechaza datos truncados o sobrantes."""
    if not isinstance(data, bytes):
        raise TypeError("RLP input must be bytes")

    def decode_at(offset: int):
        if offset >= len(data):
            raise ValueError("Truncated RLP payload")
        prefix = data[offset]
        if prefix <= 0x7f:
            return bytes([prefix]), offset + 1
        if prefix <= 0xb7:
            length = prefix - 0x80
            start, end = offset + 1, offset + 1 + length
            if end > len(data):
                raise ValueError("Truncated RLP string")
            if length == 1 and data[start] < 0x80:
                raise ValueError("Non-canonical RLP string")
            return data[start:end], end
        if prefix <= 0xbf:
            length_of_length = prefix - 0xb7
            start, end = offset + 1, offset + 1 + length_of_length
            if end > len(data):
                raise ValueError("Truncated RLP string length")
            length = int.from_bytes(data[start:end], "big")
            if length < 56 or (length_of_length > 1 and data[start] == 0):
                raise ValueError("Non-canonical RLP string length")
            value_end = end + length
            if value_end > len(data):
                raise ValueError("Truncated RLP long string")
            return data[end:value_end], value_end
        if prefix <= 0xf7:
            length = prefix - 0xc0
            start, end = offset + 1, offset + 1 + length
            if end > len(data):
                raise ValueError("Truncated RLP list")
            items, cursor = [], start
            while cursor < end:
                item, cursor = decode_at(cursor)
                items.append(item)
            if cursor != end:
                raise ValueError("Malformed RLP list")
            return items, end

        length_of_length = prefix - 0xf7
        start, end = offset + 1, offset + 1 + length_of_length
        if end > len(data):
            raise ValueError("Truncated RLP list length")
        length = int.from_bytes(data[start:end], "big")
        if length < 56 or (length_of_length > 1 and data[start] == 0):
            raise ValueError("Non-canonical RLP list length")
        list_end = end + length
        if list_end > len(data):
            raise ValueError("Truncated long RLP list")
        items, cursor = [], end
        while cursor < list_end:
            item, cursor = decode_at(cursor)
            items.append(item)
        if cursor != list_end:
            raise ValueError("Malformed RLP list")
        return items, list_end

    value, end = decode_at(0)
    if end != len(data):
        raise ValueError("Trailing bytes after RLP value")
    return value


def sha3_256(data: bytes) -> bytes:
    """Hash SHA3-256."""
    return hashlib.sha3_256(data).digest()


def keccak256(data: bytes) -> bytes:
    """Hash Keccak-256, con fallback explícito a SHA3-256."""
    try:
        from Crypto.Hash import keccak
        digest = keccak.new(digest_bits=256)
        digest.update(data)
        return digest.digest()
    except ImportError:
        return hashlib.sha3_256(data).digest()


def to_hex(data: Union[bytes, int, str]) -> str:
    if isinstance(data, bytes):
        return "0x" + data.hex()
    if isinstance(data, int):
        return "0x" + hex(data)[2:]
    if isinstance(data, str):
        return data if data.startswith("0x") else "0x" + data
    return "0x" + str(data)


def from_hex(data: str) -> bytes:
    return bytes.fromhex(data[2:] if data.startswith("0x") else data)


def to_wei(amount: Union[str, float, int], unit: str = "ether") -> int:
    units = {"wei": 1, "kwei": 10**3, "mwei": 10**6, "gwei": 10**9,
             "szabo": 10**12, "finney": 10**15, "ether": 10**18}
    if unit not in units:
        raise ValueError(f"Unknown unit: {unit}")
    return int(float(amount) * units[unit])


def from_wei(amount: int, unit: str = "ether") -> float:
    units = {"wei": 1, "kwei": 10**3, "mwei": 10**6, "gwei": 10**9,
             "szabo": 10**12, "finney": 10**15, "ether": 10**18}
    if unit not in units:
        raise ValueError(f"Unknown unit: {unit}")
    return amount / units[unit]


def generate_address() -> str:
    import secrets
    private_key = secrets.token_bytes(32)
    public_key = hashlib.sha256(private_key).digest()
    return "0x" + hashlib.sha256(public_key).digest()[-20:].hex()


def validate_address(address: str) -> bool:
    if not isinstance(address, str) or not address.startswith("0x") or len(address) != 42:
        return False
    try:
        int(address[2:], 16)
        return True
    except ValueError:
        return False


def calculate_merkle_root(leaves: list) -> str:
    if not leaves:
        return "0x" + "0" * 64
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = ["0x" + hashlib.sha256((level[i] + level[i + 1]).encode()).hexdigest()
                 for i in range(0, len(level), 2)]
    return level[0]


def format_gas_price(gas_price: int) -> str:
    return f"{from_wei(gas_price, 'gwei'):.2f} Gwei"


def format_balance(balance: int) -> str:
    return f"{from_wei(balance, 'ether'):.6f} MSC"


def calculate_gas_cost(gas_used: int, gas_price: int) -> int:
    return gas_used * gas_price


def estimate_transaction_fee(gas_limit: int, gas_price: int) -> int:
    return gas_limit * gas_price


def is_contract_address(address: str) -> bool:
    return validate_address(address)


def create_transaction_hash(tx_data: dict) -> str:
    return "0x" + hashlib.sha256(json.dumps(tx_data, sort_keys=True).encode()).hexdigest()


def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verifica una firma ECDSA DER usando cryptography."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = serialization.load_der_public_key(public_key)
        key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def generate_random_bytes(length: int) -> bytes:
    import secrets
    return secrets.token_bytes(length)


def calculate_difficulty(target_time: int, actual_time: int, current_difficulty: int) -> int:
    if actual_time < target_time:
        return current_difficulty + 1
    if actual_time > target_time * 2:
        return max(1, current_difficulty - 1)
    return current_difficulty
