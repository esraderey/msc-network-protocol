"""
Máquina virtual funcional para smart contracts
"""

import hashlib
import json
import copy
import os
from typing import Dict, Any, List, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..core.merkle_trie import MerklePatriciaTrie
from ..utils import sha3_256


class VMRevert(Exception):
    """Explicit contract revert; execution state must be rolled back."""


class SecureInternalChannel:
    """Authenticated encrypted channel for VM-to-VM internal calls.

    The channel uses AES-GCM. Nonces are random and every received nonce is
    tracked to reject replay within the channel lifetime.
    """

    AAD_PREFIX = b"MSC-VM-SECURE-CHANNEL-V1"

    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) not in (16, 24, 32):
            raise ValueError("Secure channel key must be 16, 24, or 32 bytes")
        self.key = key
        self._seen_nonces = set()

    def encrypt(self, sender: str, recipient: str, payload: bytes,
                aad: bytes = b"") -> Dict[str, str]:
        if not isinstance(payload, bytes):
            raise TypeError("Secure payload must be bytes")
        nonce = os.urandom(12)
        associated_data = self._aad(sender, recipient, aad)
        ciphertext = AESGCM(self.key).encrypt(nonce, payload, associated_data)
        return {
            "version": "MSC-VM-SECURE-1",
            "sender": str(sender),
            "recipient": str(recipient),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "aad": aad.hex(),
        }

    def decrypt(self, envelope: Dict[str, str], expected_recipient: str,
                expected_sender: Optional[str] = None) -> bytes:
        if not isinstance(envelope, dict) or envelope.get("version") != "MSC-VM-SECURE-1":
            raise ValueError("Invalid secure channel envelope")
        sender = envelope.get("sender")
        recipient = envelope.get("recipient")
        if recipient != str(expected_recipient):
            raise ValueError("Secure message recipient mismatch")
        if expected_sender is not None and sender != str(expected_sender):
            raise ValueError("Secure message sender mismatch")
        try:
            nonce = bytes.fromhex(envelope["nonce"])
            ciphertext = bytes.fromhex(envelope["ciphertext"])
            aad = bytes.fromhex(envelope.get("aad", ""))
        except (KeyError, ValueError):
            raise ValueError("Malformed secure channel envelope") from None
        if len(nonce) != 12:
            raise ValueError("Invalid secure channel nonce")
        nonce_id = (sender, recipient, nonce)
        if nonce_id in self._seen_nonces:
            raise ValueError("Secure message replay detected")
        try:
            plaintext = AESGCM(self.key).decrypt(
                nonce, ciphertext, self._aad(sender, recipient, aad)
            )
        except Exception as exc:
            raise ValueError("Secure message authentication failed") from exc
        self._seen_nonces.add(nonce_id)
        return plaintext

    @classmethod
    def _aad(cls, sender: str, recipient: str, aad: bytes) -> bytes:
        return cls.AAD_PREFIX + b"|" + str(sender).encode() + b"|" + \
            str(recipient).encode() + b"|" + aad


class MSCVirtualMachine:
    """Máquina virtual funcional para smart contracts con compilador e intérprete real"""

    WORD_BITS = 256
    WORD_MODULUS = 2 ** WORD_BITS
    MAX_STACK_ITEMS = 1024
    MAX_MEMORY_BYTES = 16 * 1024 * 1024

    def __init__(self, state_db: MerklePatriciaTrie):
        self.state_db = state_db
        self.stack = []
        self.memory = bytearray()
        self.storage = {}
        self.contract_storage = {}
        self.pc = 0  # Program counter
        self.gas_remaining = 0
        self.return_data = b""
        self.logs = []
        self.context = {}
        self.transient_storage = {}
        self._jumpdest_code = None
        self._valid_jump_destinations = set()
        
        # Protección contra re-entrancy
        self.call_depth = 0
        self.max_call_depth = 1024
        self.reentrancy_guard = {}
        self.call_stack = []
        
        # Compilador integrado
        from .compiler import MSCCompiler
        self.compiler = MSCCompiler()
        
        # Opcodes base. PUSH/DUP/SWAP se despachan por rangos en execute().
        self.opcodes = {
            0x00: self.op_stop,
            0x01: self.op_add,
            0x02: self.op_mul,
            0x03: self.op_sub,
            0x04: self.op_div,
            0x05: self.op_sdiv,
            0x06: self.op_mod,
            0x07: self.op_smod,
            0x08: self.op_addmod,
            0x09: self.op_mulmod,
            0x0a: self.op_exp,
            0x0b: self.op_signextend,
            0x10: self.op_lt,
            0x11: self.op_gt,
            0x12: self.op_slt,
            0x13: self.op_sgt,
            0x14: self.op_eq,
            0x15: self.op_iszero,
            0x16: self.op_and,
            0x17: self.op_or,
            0x18: self.op_xor,
            0x19: self.op_not,
            0x1a: self.op_byte,
            0x1b: self.op_shl,
            0x1c: self.op_shr,
            0x1d: self.op_sar,
            0x20: self.op_sha3,
            0x30: self.op_address,
            0x31: self.op_balance,
            0x32: self.op_origin,
            0x33: self.op_caller,
            0x34: self.op_callvalue,
            0x35: self.op_calldataload,
            0x36: self.op_calldatasize,
            0x37: self.op_calldatacopy,
            0x38: self.op_codesize,
            0x39: self.op_codecopy,
            0x3a: self.op_gasprice,
            0x3b: self.op_extcodesize,
            0x3c: self.op_extcodecopy,
            0x3d: self.op_returndatasize,
            0x3e: self.op_returndatacopy,
            0x3f: self.op_extcodehash,
            0x40: self.op_blockhash,
            0x41: self.op_coinbase,
            0x42: self.op_timestamp,
            0x43: self.op_number,
            0x44: self.op_prevrandao,
            0x45: self.op_gaslimit,
            0x46: self.op_chainid,
            0x47: self.op_selfbalance,
            0x48: self.op_basefee,
            0x49: self.op_blobhash,
            0x4a: self.op_blobbasefee,
            0x50: self.op_pop,
            0x51: self.op_mload,
            0x52: self.op_mstore,
            0x53: self.op_mstore8,
            0x54: self.op_sload,
            0x55: self.op_sstore,
            0x56: self.op_jump,
            0x57: self.op_jumpi,
            0x58: self.op_pc,
            0x59: self.op_msize,
            0x5a: self.op_gas,
            0x5b: self.op_jumpdest,
            0x5c: self.op_tload,
            0x5d: self.op_tstore,
            0x5e: self.op_mcopy,
            0xa0: lambda: self.op_log(0),
            0xa1: lambda: self.op_log(1),
            0xa2: lambda: self.op_log(2),
            0xa3: lambda: self.op_log(3),
            0xa4: lambda: self.op_log(4),
            0xf0: self.op_create,
            0xf1: self.op_call,
            # F2 is reserved for MSC's authenticated encrypted internal call.
            # Mapping CALLCODE to the same byte would make bytecode ambiguous.
            0xf2: self.op_secure_call,
            0xf3: self.op_return,
            0xf4: self.op_delegatecall,
            0xf5: self.op_create2,
            0xfa: self.op_staticcall,
            0xfd: self.op_revert,
            0xfe: self.op_invalid,
            0xff: self.op_selfdestruct,
        }

    def execute(self, code: bytes, gas_limit: int, context: Dict[str, Any]) -> Dict[str, Any]:
        """Ejecuta bytecode con gas, memoria dinámica y rollback atómico."""
        if not isinstance(code, bytes):
            raise TypeError("VM bytecode must be bytes")
        if not isinstance(gas_limit, int) or isinstance(gas_limit, bool) or gas_limit < 0:
            raise ValueError("gas_limit must be a non-negative integer")
        if not isinstance(context, dict):
            raise TypeError("VM context must be a dictionary")
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
        
        state_data_snapshot = dict(self.state_db.data)
        storage_snapshot = copy.deepcopy(self.contract_storage)
        transient_snapshot = copy.deepcopy(self.transient_storage)

        # Resetear estado del VM
        self.stack = []
        self.memory = bytearray()
        self.pc = 0
        self.gas_remaining = gas_limit
        self.return_data = b""
        self.logs = []
        self.context = dict(context)
        self.context['code'] = code
        self.context['static'] = bool(self.context.get('static', False))
        self._jumpdest_code = code
        self._valid_jump_destinations = self._scan_jump_destinations(code)
        self.storage = self.contract_storage.setdefault(contract_address, {})
        self.transient_storage = {}

        try:
            while self.pc < len(code):
                opcode = code[self.pc]

                if 0x5f <= opcode <= 0x7f:
                    self.op_push(opcode - 0x5f)
                    self.pc += opcode - 0x5f
                elif 0x80 <= opcode <= 0x8f:
                    self.op_dup(opcode - 0x7f)
                elif 0x90 <= opcode <= 0x9f:
                    self.op_swap(opcode - 0x8f)
                elif opcode in self.opcodes:
                    self.opcodes[opcode]()
                else:
                    raise Exception(f"Invalid opcode: 0x{opcode:02x} at PC {self.pc}")

                if len(self.stack) > self.MAX_STACK_ITEMS:
                    raise Exception("Stack overflow")
                if any(not isinstance(value, int) or not 0 <= value < self.WORD_MODULUS
                       for value in self.stack):
                    raise Exception("Invalid stack word")

                self.pc += 1

            if self.pc < len(code) and self.gas_remaining == 0:
                raise Exception("Out of gas")

            result = {
                'success': True,
                'gas_used': gas_limit - self.gas_remaining,
                'return_data': self.return_data,
                'logs': self.logs,
                'storage_changes': self.storage.copy()
            }

        except VMRevert as e:
            self.state_db.data = state_data_snapshot
            self.state_db._recompute_root()
            self.contract_storage = storage_snapshot
            self.transient_storage = transient_snapshot
            self.storage = self.contract_storage.setdefault(contract_address, {})
            self.logs = []
            result = {
                'success': False,
                'reverted': True,
                'gas_used': gas_limit - self.gas_remaining,
                'error': str(e),
                'return_data': self.return_data,
                'logs': self.logs
            }
        except Exception as e:
            self.state_db.data = state_data_snapshot
            self.state_db._recompute_root()
            self.contract_storage = storage_snapshot
            self.transient_storage = transient_snapshot
            self.storage = self.contract_storage.setdefault(contract_address, {})
            self.logs = []
            result = {
                'success': False,
                'reverted': False,
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

    @staticmethod
    def _code_aad(contract_address: str) -> bytes:
        return b"MSC-VM-ENCRYPTED-CODE-V1|" + str(contract_address).encode()

    @classmethod
    def encrypt_code(cls, code: bytes, key: bytes,
                     contract_address: str = "unknown") -> Dict[str, str]:
        """Encrypts bytecode with authenticated AES-GCM for transport/storage."""
        if not isinstance(code, bytes):
            raise TypeError("VM bytecode must be bytes")
        if not isinstance(key, bytes) or len(key) not in (16, 24, 32):
            raise ValueError("Encryption key must be 16, 24, or 32 bytes")
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(
            nonce, code, cls._code_aad(contract_address)
        )
        return {
            "version": "MSC-VM-CODE-1",
            "contract": str(contract_address),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
        }

    @classmethod
    def decrypt_code(cls, envelope: Dict[str, str], key: bytes,
                     contract_address: str = "unknown") -> bytes:
        if not isinstance(key, bytes) or len(key) not in (16, 24, 32):
            raise ValueError("Encryption key must be 16, 24, or 32 bytes")
        if not isinstance(envelope, dict) or envelope.get("version") != "MSC-VM-CODE-1":
            raise ValueError("Invalid encrypted bytecode envelope")
        if envelope.get("contract") != str(contract_address):
            raise ValueError("Encrypted bytecode contract mismatch")
        try:
            nonce = bytes.fromhex(envelope["nonce"])
            ciphertext = bytes.fromhex(envelope["ciphertext"])
        except (KeyError, ValueError):
            raise ValueError("Malformed encrypted bytecode envelope") from None
        if len(nonce) != 12:
            raise ValueError("Invalid encrypted bytecode nonce")
        try:
            return AESGCM(key).decrypt(
                nonce, ciphertext, cls._code_aad(contract_address)
            )
        except Exception as exc:
            raise ValueError("Encrypted bytecode authentication failed") from exc

    def execute_encrypted(self, envelope: Dict[str, str], key: bytes,
                          gas_limit: int, context: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypts authenticated bytecode and executes it atomically."""
        address = context.get('address', 'unknown')
        code = self.decrypt_code(envelope, key, address)
        return self.execute(code, gas_limit, context)

    def use_gas(self, amount: int):
        """Consume gas"""
        if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
            raise Exception("Invalid gas amount")
        if self.gas_remaining < amount:
            raise Exception("Out of gas")
        self.gas_remaining -= amount

    def _require_mutable(self):
        if self.context.get("static", False):
            raise Exception("State-changing opcode in static call")

    def _rollback_external_state(self, state_snapshot, storage_snapshot,
                                 transient_snapshot):
        self.state_db.data = state_snapshot
        self.state_db._recompute_root()
        self.contract_storage = storage_snapshot
        self.transient_storage = transient_snapshot
        address = self.context.get("address", "unknown")
        self.storage = self.contract_storage.setdefault(address, {})

    def _invoke_external_handler(self, handler, address: int, value: int,
                                 payload: bytes, gas: int, mode: str):
        """Invoke a trusted external-call adapter with a bounded gas budget.

        Handlers are deliberately explicit: the VM never fabricates a call
        result. A false result rolls back state changes made by the adapter,
        matching a failed call frame while allowing the caller to continue.
        """
        if not callable(handler):
            raise Exception(f"{mode.upper()} requires an explicit call handler")
        if not isinstance(gas, int) or isinstance(gas, bool) or gas < 0:
            raise Exception("Invalid external call gas")
        if gas > self.gas_remaining:
            raise Exception("External call gas exceeds remaining gas")

        state_snapshot = dict(self.state_db.data)
        storage_snapshot = copy.deepcopy(self.contract_storage)
        transient_snapshot = copy.deepcopy(self.transient_storage)
        previous_mode = self.context.get("external_call_mode")
        previous_static = self.context.get("static", False)
        self.context["external_call_mode"] = mode
        if mode == "staticcall":
            self.context["static"] = True
        try:
            result = handler(address, value, payload, gas)
        except Exception:
            self._rollback_external_state(
                state_snapshot, storage_snapshot, transient_snapshot
            )
            raise
        finally:
            if previous_mode is None:
                self.context.pop("external_call_mode", None)
            else:
                self.context["external_call_mode"] = previous_mode
            self.context["static"] = previous_static

        if isinstance(result, tuple) and len(result) == 2:
            success, returned = result
        else:
            success, returned = result, b""
        if not isinstance(success, bool) or not isinstance(returned, bytes):
            self._rollback_external_state(
                state_snapshot, storage_snapshot, transient_snapshot
            )
            raise Exception("Invalid call handler result")
        if mode == "staticcall" or not success:
            self._rollback_external_state(
                state_snapshot, storage_snapshot, transient_snapshot
            )
        return success, returned

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

    # Implementaciones básicas de opcodes
    def _pop(self) -> int:
        if not self.stack:
            raise Exception("Stack underflow")
        return self.stack.pop()

    def _push(self, value: int):
        if not isinstance(value, int):
            raise Exception("Invalid stack word")
        if len(self.stack) >= self.MAX_STACK_ITEMS:
            raise Exception("Stack overflow")
        self.stack.append(value % self.WORD_MODULUS)

    def op_push(self, size: int):
        """PUSH0..PUSH32 with strict truncated-bytecode checks."""
        if not 0 <= size <= 32:
            raise Exception("Invalid PUSH size")
        end = self.pc + 1 + size
        code = self.context['code']
        if end > len(code):
            raise Exception("Truncated PUSH immediate")
        self._push(int.from_bytes(code[self.pc + 1:end], 'big'))
        self.use_gas(3)

    def op_dup(self, depth: int):
        if not 1 <= depth <= 16 or len(self.stack) < depth:
            raise Exception("Stack underflow")
        self._push(self.stack[-depth])
        self.use_gas(3)

    def op_swap(self, depth: int):
        if not 1 <= depth <= 16 or len(self.stack) <= depth:
            raise Exception("Stack underflow")
        self.stack[-1], self.stack[-1 - depth] = self.stack[-1 - depth], self.stack[-1]
        self.use_gas(3)

    def _memory_cost(self, size: int) -> int:
        words = (size + 31) // 32
        return 3 * words + (words * words) // 512

    def _ensure_memory(self, offset: int, size: int):
        if not isinstance(offset, int) or not isinstance(size, int) or offset < 0 or size < 0:
            raise Exception("Invalid memory range")
        end = offset + size
        if end < offset or end > self.MAX_MEMORY_BYTES:
            raise Exception("Memory access out of bounds")
        if end > len(self.memory):
            self.use_gas(self._memory_cost(end) - self._memory_cost(len(self.memory)))
            self.memory.extend(b'\x00' * (end - len(self.memory)))

    def op_stop(self):
        """STOP - Termina ejecución"""
        self.pc = len(self.context['code'])

    def op_add(self):
        """ADD - Suma dos valores del stack"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self._push(a + b)
        self.use_gas(3)

    def op_mul(self):
        """MUL - Multiplica dos valores del stack"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self._push(a * b)
        self.use_gas(5)

    def op_mod(self):
        b = self._pop()
        a = self._pop()
        self._push(0 if b == 0 else a % b)
        self.use_gas(5)

    def _signed(self, value: int) -> int:
        return value - self.WORD_MODULUS if value >= self.WORD_MODULUS // 2 else value

    def op_smod(self):
        divisor = self._pop()
        dividend = self._pop()
        if divisor == 0:
            result = 0
        else:
            left = self._signed(dividend)
            right = self._signed(divisor)
            result = (abs(left) % abs(right)) * (-1 if left < 0 else 1)
        self._push(result)
        self.use_gas(5)

    def op_addmod(self):
        modulus = self._pop()
        b = self._pop()
        a = self._pop()
        self._push(0 if modulus == 0 else (a + b) % modulus)
        self.use_gas(8)

    def op_mulmod(self):
        modulus = self._pop()
        b = self._pop()
        a = self._pop()
        self._push(0 if modulus == 0 else (a * b) % modulus)
        self.use_gas(8)

    def op_exp(self):
        exponent = self._pop()
        base = self._pop()
        self._push(pow(base, exponent, self.WORD_MODULUS))
        self.use_gas(10 + 10 * max(1, (exponent.bit_length() + 7) // 8))

    def op_signextend(self):
        byte_index = self._pop()
        value = self._pop()
        if byte_index >= 32:
            result = value
        else:
            bit = byte_index * 8 + 7
            mask = (1 << (bit + 1)) - 1
            result = value | ((self.WORD_MODULUS - 1) ^ mask) if value & (1 << bit) else value & mask
        self._push(result)
        self.use_gas(5)

    def op_sub(self):
        """SUB - Resta dos valores del stack"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self._push(a - b)
        self.use_gas(3)

    def op_div(self):
        """DIV - Divide dos valores del stack"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        if b == 0:
            self._push(0)
        else:
            self._push(a // b)
        self.use_gas(5)

    def op_sdiv(self):
        divisor = self._pop()
        dividend = self._pop()
        if divisor == 0:
            result = 0
        else:
            left = self._signed(dividend)
            right = self._signed(divisor)
            result = (abs(left) // abs(right)) * (-1 if (left < 0) != (right < 0) else 1)
        self._push(result)
        self.use_gas(5)

    def op_lt(self):
        """LT - Menor que"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self._push(1 if a < b else 0)
        self.use_gas(3)

    def op_gt(self):
        """GT - Mayor que"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self._push(1 if a > b else 0)
        self.use_gas(3)

    def op_slt(self):
        b = self._signed(self._pop())
        a = self._signed(self._pop())
        self._push(1 if a < b else 0)
        self.use_gas(3)

    def op_sgt(self):
        b = self._signed(self._pop())
        a = self._signed(self._pop())
        self._push(1 if a > b else 0)
        self.use_gas(3)

    def op_eq(self):
        """EQ - Igual que"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self._push(1 if a == b else 0)
        self.use_gas(3)

    def op_iszero(self):
        """ISZERO - Es cero"""
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        self._push(1 if a == 0 else 0)
        self.use_gas(3)

    def op_and(self):
        """AND - AND lógico"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self._push(a & b)
        self.use_gas(3)

    def op_or(self):
        """OR - OR lógico"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self._push(a | b)
        self.use_gas(3)

    def op_xor(self):
        b = self._pop()
        a = self._pop()
        self._push(a ^ b)
        self.use_gas(3)

    def op_not(self):
        self._push((self._pop() ^ (self.WORD_MODULUS - 1)))
        self.use_gas(3)

    def op_byte(self):
        index = self._pop()
        value = self._pop()
        self._push(0 if index >= 32 else (value >> (8 * (31 - index))) & 0xff)
        self.use_gas(3)

    def op_shl(self):
        shift = self._pop()
        value = self._pop()
        self._push(0 if shift >= 256 else value << shift)
        self.use_gas(3)

    def op_shr(self):
        shift = self._pop()
        value = self._pop()
        self._push(0 if shift >= 256 else value >> shift)
        self.use_gas(3)

    def op_sar(self):
        shift = self._pop()
        value = self._signed(self._pop())
        if shift >= 256:
            result = self.WORD_MODULUS - 1 if value < 0 else 0
        else:
            result = value >> shift
        self._push(result)
        self.use_gas(3)

    def op_sha3(self):
        """SHA3 - Hash SHA3"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        size = self.stack.pop()
        offset = self.stack.pop()
        
        self._ensure_memory(offset, size)

        # Obtener datos de memoria
        data = bytes(self.memory[offset:offset + size])
        import hashlib
        hash_result = int.from_bytes(sha3_256(data), 'big')
        self._push(hash_result)
        self.use_gas(30 + size)

    def op_address(self):
        """ADDRESS - Dirección del contrato actual"""
        address = self.context.get('address', '0x0')
        self._push(int(address, 16) if address.startswith('0x') else 0)
        self.use_gas(2)

    def op_balance(self):
        """BALANCE - Balance de una cuenta"""
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        address = self.stack.pop()
        address_hex = f"0x{address:040x}"
        encoded = self.state_db.get(f"account:{address_hex}".encode())
        balance = 0
        if encoded:
            try:
                balance = int(json.loads(encoded.decode()).get("balance", 0))
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                raise Exception("Invalid account state") from exc
        self._push(balance)
        self.use_gas(400)

    def op_origin(self):
        """ORIGIN - Dirección del originador de la transacción"""
        origin = self.context.get('origin', '0x0')
        self._push(int(origin, 16) if origin.startswith('0x') else 0)
        self.use_gas(2)

    def op_caller(self):
        """CALLER - Dirección del llamador"""
        caller = self.context.get('caller', '0x0')
        self._push(int(caller, 16) if caller.startswith('0x') else 0)
        self.use_gas(2)

    def op_callvalue(self):
        """CALLVALUE - Valor enviado con la llamada"""
        value = self.context.get('value', 0)
        self._push(value)
        self.use_gas(2)

    def _context_bytes(self, name: str) -> bytes:
        value = self.context.get(name, b"")
        if isinstance(value, str):
            try:
                return bytes.fromhex(value[2:] if value.startswith("0x") else value)
            except ValueError as exc:
                raise Exception(f"Invalid {name}") from exc
        if not isinstance(value, bytes):
            raise Exception(f"Invalid {name}")
        return value

    def _context_word(self, name: str, default: int = 0) -> int:
        value = self.context.get(name, default)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise Exception(f"Invalid {name}")
        return value % self.WORD_MODULUS

    def _copy_bytes_to_memory(self, memory_offset: int, source: bytes,
                              source_offset: int, size: int):
        self._ensure_memory(memory_offset, size)
        copied = source[source_offset:source_offset + size]
        self.memory[memory_offset:memory_offset + size] = copied.ljust(size, b"\x00")

    def op_calldataload(self):
        offset = self._pop()
        data = self._context_bytes("calldata")
        self._push(int.from_bytes(data[offset:offset + 32].ljust(32, b"\x00"), "big"))
        self.use_gas(3)

    def op_calldatasize(self):
        self._push(len(self._context_bytes("calldata")))
        self.use_gas(2)

    def op_calldatacopy(self):
        memory_offset = self._pop()
        data_offset = self._pop()
        size = self._pop()
        self._copy_bytes_to_memory(memory_offset, self._context_bytes("calldata"), data_offset, size)
        self.use_gas(3 + 3 * ((size + 31) // 32))

    def op_codesize(self):
        self._push(len(self.context.get("code", b"")))
        self.use_gas(2)

    def op_codecopy(self):
        memory_offset = self._pop()
        code_offset = self._pop()
        size = self._pop()
        self._copy_bytes_to_memory(memory_offset, self.context.get("code", b""), code_offset, size)
        self.use_gas(3 + 3 * ((size + 31) // 32))

    def op_gasprice(self):
        self._push(self._context_word("gas_price"))
        self.use_gas(2)

    def _external_code(self, address: int) -> bytes:
        handler = self.context.get("external_code_handler")
        if callable(handler):
            code = handler(address)
            if not isinstance(code, bytes):
                raise Exception("Invalid external code handler result")
            return code
        encoded = self.state_db.get(f"contract:0x{address:040x}".encode())
        return encoded or b""

    def op_extcodesize(self):
        self._push(len(self._external_code(self._pop())))
        self.use_gas(100)

    def op_extcodecopy(self):
        address = self._pop()
        memory_offset = self._pop()
        code_offset = self._pop()
        size = self._pop()
        self._copy_bytes_to_memory(memory_offset, self._external_code(address), code_offset, size)
        self.use_gas(100 + 3 * ((size + 31) // 32))

    def op_extcodehash(self):
        """EXTCODEHASH - Hash external code, or zero for an absent account."""
        address = self._pop()
        code = self._external_code(address)
        self._push(0 if not code else int.from_bytes(sha3_256(code), "big"))
        self.use_gas(100)

    def op_returndatasize(self):
        self._push(len(self.return_data))
        self.use_gas(2)

    def op_returndatacopy(self):
        memory_offset = self._pop()
        data_offset = self._pop()
        size = self._pop()
        if data_offset + size > len(self.return_data):
            raise Exception("Return data out of bounds")
        self._copy_bytes_to_memory(memory_offset, self.return_data, data_offset, size)
        self.use_gas(3 + 3 * ((size + 31) // 32))

    def op_blockhash(self):
        number = self._pop()
        handler = self.context.get("blockhash_handler")
        if callable(handler):
            value = handler(number)
            if not isinstance(value, int) or value < 0:
                raise Exception("Invalid block hash handler result")
            self._push(value)
        else:
            hashes = self.context.get("block_hashes", {})
            value = hashes.get(number, 0) if isinstance(hashes, dict) else 0
            self._push(value if isinstance(value, int) else int.from_bytes(value, "big"))
        self.use_gas(20)

    def op_coinbase(self):
        self._push(self._context_word("coinbase"))
        self.use_gas(2)

    def op_timestamp(self):
        self._push(self._context_word("timestamp"))
        self.use_gas(2)

    def op_number(self):
        self._push(self._context_word("block_number"))
        self.use_gas(2)

    def op_prevrandao(self):
        self._push(self._context_word("prevrandao"))
        self.use_gas(2)

    def op_gaslimit(self):
        self._push(self._context_word("gas_limit"))
        self.use_gas(2)

    def op_chainid(self):
        self._push(self._context_word("chain_id"))
        self.use_gas(2)

    def op_selfbalance(self):
        address = self.context.get("address", "0x0")
        encoded = self.state_db.get(f"account:{address}".encode())
        balance = 0
        if encoded:
            try:
                balance = int(json.loads(encoded.decode()).get("balance", 0))
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                raise Exception("Invalid account state") from exc
        self._push(balance)
        self.use_gas(5)

    def op_basefee(self):
        self._push(self._context_word("base_fee"))
        self.use_gas(2)

    def op_blobhash(self):
        """BLOBHASH - Read a versioned blob hash from block context."""
        index = self._pop()
        blob_hashes = self.context.get("blob_hashes", {})
        value = 0
        if isinstance(blob_hashes, dict):
            value = blob_hashes.get(index, 0)
        elif isinstance(blob_hashes, (list, tuple)) and index < len(blob_hashes):
            value = blob_hashes[index]
        else:
            raise Exception("Invalid blob hash context")
        if isinstance(value, bytes):
            if len(value) > 32:
                raise Exception("Invalid blob hash")
            value = int.from_bytes(value, "big")
        if not isinstance(value, int) or value < 0:
            raise Exception("Invalid blob hash")
        self._push(value)
        self.use_gas(3)

    def op_blobbasefee(self):
        self._push(self._context_word("blob_base_fee"))
        self.use_gas(2)

    def op_log(self, topics_count: int):
        self._require_mutable()
        size = self._pop()
        offset = self._pop()
        topics = [self._pop() for _ in range(topics_count)]
        self._ensure_memory(offset, size)
        self.logs.append({
            "address": self.context.get("address", "0x0"),
            "topics": topics,
            "data": bytes(self.memory[offset:offset + size]),
        })
        self.use_gas(375 + 375 * topics_count + 8 * size)

    def op_pop(self):
        """POP - Remueve elemento del stack"""
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        self.stack.pop()
        self.use_gas(2)

    def op_mload(self):
        """MLOAD - Carga desde memoria"""
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        offset = self.stack.pop()
        self._ensure_memory(offset, 32)
        
        # Cargar 32 bytes desde memoria
        data = self.memory[offset:offset + 32]
        value = int.from_bytes(data, 'big')
        self._push(value)
        self.use_gas(3)

    def op_mstore(self):
        """MSTORE - Almacena en memoria"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        value = self.stack.pop()
        offset = self.stack.pop()
        self._ensure_memory(offset, 32)
        
        # Almacenar 32 bytes en memoria
        data = (value % (2**256)).to_bytes(32, 'big')
        self.memory[offset:offset + 32] = data
        self.use_gas(3)

    def op_mstore8(self):
        value = self._pop()
        offset = self._pop()
        self._ensure_memory(offset, 1)
        self.memory[offset] = value & 0xff
        self.use_gas(3)

    def op_msize(self):
        self._push(len(self.memory))
        self.use_gas(2)

    def op_sload(self):
        """SLOAD - Carga desde storage"""
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        key = self.stack.pop()
        
        value = self.storage.get(key, 0)
        self._push(value)
        self.use_gas(200)

    def op_sstore(self):
        """SSTORE - Almacena en storage"""
        self._require_mutable()
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        value = self.stack.pop()
        key = self.stack.pop()
        
        self.use_gas(20000 if value != 0 else 5000)
        self.storage[key] = value

    def op_jump(self):
        """JUMP - Salto incondicional"""
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        dest = self.stack.pop()
        self._validate_jump_destination(dest)
        # execute() increments PC after each opcode; land on JUMPDEST so it
        # is actually executed and charged instead of skipping it.
        self.pc = dest - 1
        self.use_gas(8)

    def op_jumpi(self):
        """JUMPI - Salto condicional"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        dest = self.stack.pop()
        condition = self.stack.pop()
        
        if condition != 0:
            self._validate_jump_destination(dest)
            self.pc = dest - 1
        self.use_gas(10)

    def op_pc(self):
        """PC - Program counter"""
        self._push(self.pc)
        self.use_gas(2)

    def op_gas(self):
        """GAS - Gas restante"""
        self._push(self.gas_remaining)
        self.use_gas(2)

    def op_jumpdest(self):
        """JUMPDEST - Destino de salto"""
        # No hace nada, solo marca una posición válida para saltos
        self.use_gas(1)

    def op_tload(self):
        key = self._pop()
        self._push(self.transient_storage.get(key, 0))
        self.use_gas(100)

    def op_tstore(self):
        self._require_mutable()
        value = self._pop()
        key = self._pop()
        self.transient_storage[key] = value
        self.use_gas(100)

    def op_mcopy(self):
        """MCOPY - Copy memory with overlap-safe semantics."""
        destination = self._pop()
        source = self._pop()
        size = self._pop()
        self._ensure_memory(source, size)
        self._ensure_memory(destination, size)
        copied = bytes(self.memory[source:source + size])
        self.memory[destination:destination + size] = copied
        self.use_gas(3 + 3 * ((size + 31) // 32))

    def op_create(self):
        """CREATE - Crear nuevo contrato"""
        self._require_mutable()
        if len(self.stack) < 3:
            raise Exception("Stack underflow")
        value = self.stack.pop()
        offset = self.stack.pop()
        size = self.stack.pop()
        self._ensure_memory(offset, size)
        code = bytes(self.memory[offset:offset + size])
        caller = self.context.get('address', '0x0')
        nonce = self.context.get('nonce', 0)
        if not isinstance(nonce, int) or isinstance(nonce, bool) or nonce < 0:
            raise Exception("Invalid CREATE nonce")
        contract_address = "0x" + hashlib.sha256(
            f"{caller}:{nonce}:".encode() + code
        ).hexdigest()[-40:]
        self.use_gas(32000 + 200 * len(code))
        self.state_db.put(f"contract:{contract_address}".encode(), code)
        self._push(int(contract_address, 16))

    def op_call(self):
        """CALL - Llamar a otro contrato"""
        if len(self.stack) < 7:
            raise Exception("Stack underflow")
        
        # Parámetros de la llamada
        gas = self.stack.pop()
        address = self.stack.pop()
        value = self.stack.pop()
        args_offset = self.stack.pop()
        args_size = self.stack.pop()
        ret_offset = self.stack.pop()
        ret_size = self.stack.pop()
        
        if not all(isinstance(item, int) and item >= 0 for item in
                   (args_offset, args_size, ret_offset, ret_size)):
            raise Exception("Invalid CALL memory range")
        if self.context.get("static", False) and value != 0:
            raise Exception("CALL with value in static call")
        self._ensure_memory(args_offset, args_size)
        self._ensure_memory(ret_offset, ret_size)
        self.use_gas(700)
        handler = self.context.get('call_handler')
        success, returned = self._invoke_external_handler(
            handler, address, value,
            bytes(self.memory[args_offset:args_offset + args_size]), gas, "call"
        )
        self.memory[ret_offset:ret_offset + ret_size] = returned[:ret_size].ljust(ret_size, b'\x00')
        self.return_data = returned
        self._push(1 if success else 0)

    def op_delegatecall(self):
        """DELEGATECALL - External code with the caller's storage context."""
        if len(self.stack) < 6:
            raise Exception("Stack underflow")
        gas = self._pop()
        address = self._pop()
        args_offset = self._pop()
        args_size = self._pop()
        ret_offset = self._pop()
        ret_size = self._pop()
        if self.context.get("static", False):
            raise Exception("DELEGATECALL in static call")
        self._ensure_memory(args_offset, args_size)
        self._ensure_memory(ret_offset, ret_size)
        self.use_gas(700)
        handler = self.context.get("delegate_call_handler")
        if handler is None:
            handler = self.context.get("call_handler")
        value = self._context_word("callvalue", self._context_word("value"))
        success, returned = self._invoke_external_handler(
            handler, address, value,
            bytes(self.memory[args_offset:args_offset + args_size]), gas,
            "delegatecall"
        )
        self.memory[ret_offset:ret_offset + ret_size] = returned[:ret_size].ljust(ret_size, b"\x00")
        self.return_data = returned
        self._push(1 if success else 0)

    def op_create2(self):
        """CREATE2 - Deterministic contract creation."""
        self._require_mutable()
        if len(self.stack) < 4:
            raise Exception("Stack underflow")
        salt = self._pop()
        size = self._pop()
        offset = self._pop()
        _value = self._pop()
        self._ensure_memory(offset, size)
        code = bytes(self.memory[offset:offset + size])
        deployer = self.context.get("address", "0x0")
        try:
            deployer_bytes = bytes.fromhex(deployer[2:] if deployer.startswith("0x") else deployer)
        except (AttributeError, ValueError):
            raise Exception("Invalid CREATE2 deployer") from None
        if len(deployer_bytes) != 20:
            raise Exception("Invalid CREATE2 deployer")
        address_bytes = sha3_256(
            b"\xff" + deployer_bytes + salt.to_bytes(32, "big") + sha3_256(code)
        )[-20:]
        contract_address = "0x" + address_bytes.hex()
        self.use_gas(32000 + 200 * len(code))
        self.state_db.put(f"contract:{contract_address}".encode(), code)
        self._push(int.from_bytes(address_bytes, "big"))

    def op_staticcall(self):
        """STATICCALL - External call with state mutation disabled."""
        if len(self.stack) < 6:
            raise Exception("Stack underflow")
        gas = self._pop()
        address = self._pop()
        args_offset = self._pop()
        args_size = self._pop()
        ret_offset = self._pop()
        ret_size = self._pop()
        self._ensure_memory(args_offset, args_size)
        self._ensure_memory(ret_offset, ret_size)
        self.use_gas(700)
        handler = self.context.get("static_call_handler")
        if handler is None:
            handler = self.context.get("call_handler")
        success, returned = self._invoke_external_handler(
            handler, address, 0,
            bytes(self.memory[args_offset:args_offset + args_size]), gas,
            "staticcall"
        )
        self.memory[ret_offset:ret_offset + ret_size] = returned[:ret_size].ljust(ret_size, b"\x00")
        self.return_data = returned
        self._push(1 if success else 0)

    def op_secure_call(self):
        """F2: authenticated encrypted internal call over SecureInternalChannel."""
        if len(self.stack) < 7:
            raise Exception("Stack underflow")
        gas = self._pop()
        address = self._pop()
        value = self._pop()
        args_offset = self._pop()
        args_size = self._pop()
        ret_offset = self._pop()
        ret_size = self._pop()
        self._ensure_memory(args_offset, args_size)
        self._ensure_memory(ret_offset, ret_size)
        channel = self.context.get('secure_channel')
        handler = self.context.get('secure_call_handler')
        if not isinstance(channel, SecureInternalChannel) or not callable(handler):
            raise Exception("SECURE_CALL requires a secure channel and handler")
        self.use_gas(900)
        if gas > self.gas_remaining:
            raise Exception("External call gas exceeds remaining gas")
        sender = self.context.get('address', 'unknown')
        recipient = f"0x{address:040x}"
        envelope = channel.encrypt(
            sender, recipient,
            bytes(self.memory[args_offset:args_offset + args_size]),
            aad=str(value).encode()
        )
        state_snapshot = dict(self.state_db.data)
        storage_snapshot = copy.deepcopy(self.contract_storage)
        transient_snapshot = copy.deepcopy(self.transient_storage)
        try:
            response = handler(envelope, gas)
            payload = channel.decrypt(response, sender, recipient)
        except Exception:
            self._rollback_external_state(
                state_snapshot, storage_snapshot, transient_snapshot
            )
            raise
        self.memory[ret_offset:ret_offset + ret_size] = payload[:ret_size].ljust(ret_size, b'\x00')
        self.return_data = payload
        self._push(1)

    def op_return(self):
        """RETURN - Retorna datos"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        size = self.stack.pop()
        offset = self.stack.pop()
        self._ensure_memory(offset, size)
        
        # Obtener datos de memoria
        self.return_data = bytes(self.memory[offset:offset + size])
        self.pc = len(self.context['code'])
        self.use_gas(0)

    def op_revert(self):
        """REVERT: returns data and forces atomic state rollback."""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        size = self._pop()
        offset = self._pop()
        self._ensure_memory(offset, size)
        self.return_data = bytes(self.memory[offset:offset + size])
        raise VMRevert(f"REVERT: {self.return_data.hex()}")

    def op_invalid(self):
        raise Exception("INVALID opcode")

    def op_selfdestruct(self):
        """SELFDESTRUCT - Destruir contrato"""
        self._require_mutable()
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        beneficiary = self.stack.pop()
        
        handler = self.context.get('selfdestruct_handler')
        if not callable(handler):
            raise Exception("SELFDESTRUCT requires an explicit state handler")
        handler(beneficiary)
        self.pc = len(self.context['code'])
        self.use_gas(5000)

    def _validate_jump_destination(self, destination: int):
        code = self.context.get('code', b'')
        if code != self._jumpdest_code:
            self._jumpdest_code = code
            self._valid_jump_destinations = self._scan_jump_destinations(code)
        if (not isinstance(destination, int) or destination not in
                self._valid_jump_destinations):
            raise Exception("Invalid jump destination")

    @staticmethod
    def _scan_jump_destinations(code: bytes):
        destinations = set()
        pc = 0
        while pc < len(code):
            opcode = code[pc]
            if opcode == 0x5b:
                destinations.add(pc)
                pc += 1
            elif 0x60 <= opcode <= 0x7f:
                pc += 1 + (opcode - 0x5f)
            else:
                pc += 1
        return destinations
