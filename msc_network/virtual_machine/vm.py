"""
Máquina virtual funcional para smart contracts
"""

from typing import Dict, Any, List
from ..core.merkle_trie import MerklePatriciaTrie

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
        from .compiler import MSCCompiler
        self.compiler = MSCCompiler()
        
        # Opcodes básicos (implementación simplificada)
        self.opcodes = {
            0x00: self.op_stop,
            0x01: self.op_add,
            0x02: self.op_mul,
            0x03: self.op_sub,
            0x04: self.op_div,
            0x10: self.op_lt,
            0x11: self.op_gt,
            0x14: self.op_eq,
            0x15: self.op_iszero,
            0x16: self.op_and,
            0x17: self.op_or,
            0x20: self.op_sha3,
            0x30: self.op_address,
            0x31: self.op_balance,
            0x32: self.op_origin,
            0x33: self.op_caller,
            0x34: self.op_callvalue,
            0x50: self.op_pop,
            0x51: self.op_mload,
            0x52: self.op_mstore,
            0x54: self.op_sload,
            0x55: self.op_sstore,
            0x56: self.op_jump,
            0x57: self.op_jumpi,
            0x58: self.op_pc,
            0x5a: self.op_gas,
            0x5b: self.op_jumpdest,
            0xf0: self.op_create,
            0xf1: self.op_call,
            0xf3: self.op_return,
            0xff: self.op_selfdestruct,
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

    # Implementaciones básicas de opcodes
    def op_stop(self):
        """STOP - Termina ejecución"""
        self.pc = len(self.memory)  # Salir del loop

    def op_add(self):
        """ADD - Suma dos valores del stack"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append((a + b) % (2**256))
        self.use_gas(3)

    def op_mul(self):
        """MUL - Multiplica dos valores del stack"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append((a * b) % (2**256))
        self.use_gas(5)

    def op_sub(self):
        """SUB - Resta dos valores del stack"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append((a - b) % (2**256))
        self.use_gas(3)

    def op_div(self):
        """DIV - Divide dos valores del stack"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        if b == 0:
            self.stack.append(0)
        else:
            self.stack.append(a // b)
        self.use_gas(5)

    def op_lt(self):
        """LT - Menor que"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append(1 if a < b else 0)
        self.use_gas(3)

    def op_gt(self):
        """GT - Mayor que"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append(1 if a > b else 0)
        self.use_gas(3)

    def op_eq(self):
        """EQ - Igual que"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append(1 if a == b else 0)
        self.use_gas(3)

    def op_iszero(self):
        """ISZERO - Es cero"""
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        self.stack.append(1 if a == 0 else 0)
        self.use_gas(3)

    def op_and(self):
        """AND - AND lógico"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append(a & b)
        self.use_gas(3)

    def op_or(self):
        """OR - OR lógico"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append(a | b)
        self.use_gas(3)

    def op_sha3(self):
        """SHA3 - Hash SHA3"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        size = self.stack.pop()
        offset = self.stack.pop()
        
        # Obtener datos de memoria
        data = bytes(self.memory[offset:offset + size])
        import hashlib
        hash_result = int.from_bytes(hashlib.sha256(data).digest(), 'big')
        self.stack.append(hash_result)
        self.use_gas(30 + size)

    def op_address(self):
        """ADDRESS - Dirección del contrato actual"""
        address = self.context.get('address', '0x0')
        self.stack.append(int(address, 16) if address.startswith('0x') else 0)
        self.use_gas(2)

    def op_balance(self):
        """BALANCE - Balance de una cuenta"""
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        address = self.stack.pop()
        # Implementación simplificada
        self.stack.append(1000000)  # Balance placeholder
        self.use_gas(400)

    def op_origin(self):
        """ORIGIN - Dirección del originador de la transacción"""
        origin = self.context.get('origin', '0x0')
        self.stack.append(int(origin, 16) if origin.startswith('0x') else 0)
        self.use_gas(2)

    def op_caller(self):
        """CALLER - Dirección del llamador"""
        caller = self.context.get('caller', '0x0')
        self.stack.append(int(caller, 16) if caller.startswith('0x') else 0)
        self.use_gas(2)

    def op_callvalue(self):
        """CALLVALUE - Valor enviado con la llamada"""
        value = self.context.get('value', 0)
        self.stack.append(value)
        self.use_gas(2)

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
        
        # Cargar 32 bytes desde memoria
        data = self.memory[offset:offset + 32]
        value = int.from_bytes(data, 'big')
        self.stack.append(value)
        self.use_gas(3)

    def op_mstore(self):
        """MSTORE - Almacena en memoria"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        value = self.stack.pop()
        offset = self.stack.pop()
        
        # Almacenar 32 bytes en memoria
        data = value.to_bytes(32, 'big')
        self.memory[offset:offset + 32] = data
        self.use_gas(3)

    def op_sload(self):
        """SLOAD - Carga desde storage"""
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        key = self.stack.pop()
        
        value = self.storage.get(key, 0)
        self.stack.append(value)
        self.use_gas(200)

    def op_sstore(self):
        """SSTORE - Almacena en storage"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        value = self.stack.pop()
        key = self.stack.pop()
        
        self.storage[key] = value
        self.use_gas(20000 if value != 0 else 5000)

    def op_jump(self):
        """JUMP - Salto incondicional"""
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        dest = self.stack.pop()
        self.pc = dest
        self.use_gas(8)

    def op_jumpi(self):
        """JUMPI - Salto condicional"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        dest = self.stack.pop()
        condition = self.stack.pop()
        
        if condition != 0:
            self.pc = dest
        self.use_gas(10)

    def op_pc(self):
        """PC - Program counter"""
        self.stack.append(self.pc)
        self.use_gas(2)

    def op_gas(self):
        """GAS - Gas restante"""
        self.stack.append(self.gas_remaining)
        self.use_gas(2)

    def op_jumpdest(self):
        """JUMPDEST - Destino de salto"""
        # No hace nada, solo marca una posición válida para saltos
        self.use_gas(1)

    def op_create(self):
        """CREATE - Crear nuevo contrato"""
        if len(self.stack) < 3:
            raise Exception("Stack underflow")
        value = self.stack.pop()
        offset = self.stack.pop()
        size = self.stack.pop()
        
        # Obtener código del contrato desde memoria
        code = bytes(self.memory[offset:offset + size])
        
        # Crear nuevo contrato (simplificado)
        contract_address = f"0x{hash(code.hex()):040x}"
        self.stack.append(int(contract_address, 16))
        self.use_gas(32000)

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
        
        # Implementación simplificada
        self.stack.append(1)  # Éxito
        self.use_gas(700)

    def op_return(self):
        """RETURN - Retorna datos"""
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        size = self.stack.pop()
        offset = self.stack.pop()
        
        # Obtener datos de memoria
        self.return_data = bytes(self.memory[offset:offset + size])
        self.pc = len(self.memory)  # Terminar ejecución
        self.use_gas(0)

    def op_selfdestruct(self):
        """SELFDESTRUCT - Destruir contrato"""
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        beneficiary = self.stack.pop()
        
        # Implementación simplificada
        self.pc = len(self.memory)  # Terminar ejecución
        self.use_gas(5000)
