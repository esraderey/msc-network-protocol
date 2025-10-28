"""
Compilador MSC para smart contracts
"""

import re
from typing import Dict, List, Any

class MSCCompiler:
    """Compilador funcional para smart contracts MSC"""

    def __init__(self):
        self.opcodes = {
            'STOP': 0x00,
            'ADD': 0x01,
            'MUL': 0x02,
            'SUB': 0x03,
            'DIV': 0x04,
            'LT': 0x10,
            'GT': 0x11,
            'EQ': 0x14,
            'ISZERO': 0x15,
            'AND': 0x16,
            'OR': 0x17,
            'SHA3': 0x20,
            'ADDRESS': 0x30,
            'BALANCE': 0x31,
            'ORIGIN': 0x32,
            'CALLER': 0x33,
            'CALLVALUE': 0x34,
            'POP': 0x50,
            'MLOAD': 0x51,
            'MSTORE': 0x52,
            'SLOAD': 0x54,
            'SSTORE': 0x55,
            'JUMP': 0x56,
            'JUMPI': 0x57,
            'PC': 0x58,
            'GAS': 0x5a,
            'JUMPDEST': 0x5b,
            'CREATE': 0xf0,
            'CALL': 0xf1,
            'RETURN': 0xf3,
            'SELFDESTRUCT': 0xff,
        }
        
        self.push_opcodes = {
            1: 0x60, 2: 0x61, 3: 0x62, 4: 0x63, 5: 0x64,
            6: 0x65, 7: 0x66, 8: 0x67, 9: 0x68, 10: 0x69,
            11: 0x6a, 12: 0x6b, 13: 0x6c, 14: 0x6d, 15: 0x6e,
            16: 0x6f, 17: 0x70, 18: 0x71, 19: 0x72, 20: 0x73,
            21: 0x74, 22: 0x75, 23: 0x76, 24: 0x77, 25: 0x78,
            26: 0x79, 27: 0x7a, 28: 0x7b, 29: 0x7c, 30: 0x7d,
            31: 0x7e, 32: 0x7f
        }

    def compile(self, source_code: str) -> bytes:
        """Compila código fuente a bytecode"""
        # Limpiar código fuente
        source_code = self._clean_source(source_code)
        
        # Parsear código
        instructions = self._parse_instructions(source_code)
        
        # Compilar a bytecode
        bytecode = self._compile_instructions(instructions)
        
        return bytecode

    def _clean_source(self, source_code: str) -> str:
        """Limpia el código fuente"""
        # Remover comentarios
        source_code = re.sub(r'//.*$', '', source_code, flags=re.MULTILINE)
        source_code = re.sub(r'/\*.*?\*/', '', source_code, flags=re.DOTALL)
        
        # Normalizar espacios
        source_code = re.sub(r'\s+', ' ', source_code)
        source_code = source_code.strip()
        
        return source_code

    def _parse_instructions(self, source_code: str) -> List[Dict[str, Any]]:
        """Parsea instrucciones del código fuente"""
        instructions = []
        lines = source_code.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Parsear instrucción
            instruction = self._parse_instruction(line)
            if instruction:
                instructions.append(instruction)
        
        return instructions

    def _parse_instruction(self, line: str) -> Dict[str, Any]:
        """Parsea una instrucción individual"""
        parts = line.split()
        if not parts:
            return None
        
        opcode = parts[0].upper()
        
        instruction = {
            'opcode': opcode,
            'args': []
        }
        
        # Parsear argumentos
        for arg in parts[1:]:
            if arg.startswith('0x'):
                # Valor hexadecimal
                instruction['args'].append(int(arg, 16))
            elif arg.isdigit():
                # Valor decimal
                instruction['args'].append(int(arg))
            else:
                # Etiqueta o identificador
                instruction['args'].append(arg)
        
        return instruction

    def _compile_instructions(self, instructions: List[Dict[str, Any]]) -> bytes:
        """Compila instrucciones a bytecode"""
        bytecode = bytearray()
        labels = {}
        
        # Primera pasada: encontrar etiquetas
        pc = 0
        for instruction in instructions:
            if instruction['opcode'] == 'LABEL':
                label_name = instruction['args'][0]
                labels[label_name] = pc
            else:
                pc += self._get_instruction_size(instruction)
        
        # Segunda pasada: compilar
        pc = 0
        for instruction in instructions:
            if instruction['opcode'] == 'LABEL':
                continue
                
            compiled = self._compile_instruction(instruction, labels, pc)
            bytecode.extend(compiled)
            pc += len(compiled)
        
        return bytes(bytecode)

    def _get_instruction_size(self, instruction: Dict[str, Any]) -> int:
        """Calcula el tamaño de una instrucción"""
        opcode = instruction['opcode']
        
        if opcode in self.opcodes:
            return 1 + sum(self._get_arg_size(arg) for arg in instruction['args'])
        elif opcode.startswith('PUSH'):
            # PUSH1, PUSH2, etc.
            size = int(opcode[4:])
            return 1 + size
        else:
            return 1

    def _get_arg_size(self, arg: Any) -> int:
        """Calcula el tamaño de un argumento"""
        if isinstance(arg, int):
            if arg < 256:
                return 1
            elif arg < 65536:
                return 2
            elif arg < 16777216:
                return 3
            else:
                return 4
        else:
            return 0  # Etiquetas se resuelven después

    def _compile_instruction(self, instruction: Dict[str, Any], labels: Dict[str, int], pc: int) -> bytes:
        """Compila una instrucción individual"""
        opcode = instruction['opcode']
        args = instruction['args']
        
        if opcode in self.opcodes:
            # Opcode simple
            bytecode = bytearray([self.opcodes[opcode]])
            
            # Añadir argumentos
            for arg in args:
                if isinstance(arg, str) and arg in labels:
                    # Resolver etiqueta
                    value = labels[arg] - pc
                    bytecode.extend(value.to_bytes(4, 'big'))
                elif isinstance(arg, int):
                    # Valor numérico
                    if arg < 256:
                        bytecode.append(arg)
                    else:
                        bytecode.extend(arg.to_bytes(4, 'big'))
            
            return bytes(bytecode)
        
        elif opcode.startswith('PUSH'):
            # Instrucción PUSH
            size = int(opcode[4:])
            if size not in self.push_opcodes:
                raise ValueError(f"Invalid PUSH size: {size}")
            
            if not args:
                raise ValueError("PUSH requires an argument")
            
            value = args[0]
            if isinstance(value, str) and value in labels:
                value = labels[value] - pc
            
            # Asegurar que el valor cabe en el tamaño especificado
            max_value = (1 << (size * 8)) - 1
            if value > max_value:
                value = value & max_value
            
            bytecode = bytearray([self.push_opcodes[size]])
            bytecode.extend(value.to_bytes(size, 'big'))
            
            return bytes(bytecode)
        
        else:
            raise ValueError(f"Unknown opcode: {opcode}")

    def decompile(self, bytecode: bytes) -> str:
        """Descompila bytecode a código fuente"""
        instructions = []
        i = 0
        
        while i < len(bytecode):
            opcode = bytecode[i]
            
            # Buscar opcode
            opcode_name = None
            for name, code in self.opcodes.items():
                if code == opcode:
                    opcode_name = name
                    break
            
            if opcode_name:
                instructions.append(opcode_name)
                i += 1
            elif 0x60 <= opcode <= 0x7f:
                # Instrucción PUSH
                size = opcode - 0x5f
                if i + size < len(bytecode):
                    value = int.from_bytes(bytecode[i+1:i+1+size], 'big')
                    instructions.append(f"PUSH{size} 0x{value:x}")
                    i += 1 + size
                else:
                    instructions.append(f"INVALID_PUSH{size}")
                    i += 1
            else:
                instructions.append(f"UNKNOWN_0x{opcode:02x}")
                i += 1
        
        return '\n'.join(instructions)
