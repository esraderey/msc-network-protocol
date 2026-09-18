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
            'SDIV': 0x05,
            'MOD': 0x06,
            'SMOD': 0x07,
            'ADDMOD': 0x08,
            'MULMOD': 0x09,
            'EXP': 0x0a,
            'SIGNEXTEND': 0x0b,
            'LT': 0x10,
            'GT': 0x11,
            'SLT': 0x12,
            'SGT': 0x13,
            'EQ': 0x14,
            'ISZERO': 0x15,
            'AND': 0x16,
            'OR': 0x17,
            'XOR': 0x18,
            'NOT': 0x19,
            'BYTE': 0x1a,
            'SHL': 0x1b,
            'SHR': 0x1c,
            'SAR': 0x1d,
            'SHA3': 0x20,
            'ADDRESS': 0x30,
            'BALANCE': 0x31,
            'ORIGIN': 0x32,
            'CALLER': 0x33,
            'CALLVALUE': 0x34,
            'CALLDATALOAD': 0x35,
            'CALLDATASIZE': 0x36,
            'CALLDATACOPY': 0x37,
            'CODESIZE': 0x38,
            'CODECOPY': 0x39,
            'GASPRICE': 0x3a,
            'EXTCODESIZE': 0x3b,
            'EXTCODECOPY': 0x3c,
            'RETURNDATASIZE': 0x3d,
            'RETURNDATACOPY': 0x3e,
            'EXTCODEHASH': 0x3f,
            'BLOCKHASH': 0x40,
            'COINBASE': 0x41,
            'TIMESTAMP': 0x42,
            'NUMBER': 0x43,
            'PREVRANDAO': 0x44,
            'GASLIMIT': 0x45,
            'CHAINID': 0x46,
            'SELFBALANCE': 0x47,
            'BASEFEE': 0x48,
            'BLOBHASH': 0x49,
            'BLOBBASEFEE': 0x4a,
            'POP': 0x50,
            'MLOAD': 0x51,
            'MSTORE': 0x52,
            'MSTORE8': 0x53,
            'SLOAD': 0x54,
            'SSTORE': 0x55,
            'JUMP': 0x56,
            'JUMPI': 0x57,
            'PC': 0x58,
            'MSIZE': 0x59,
            'GAS': 0x5a,
            'JUMPDEST': 0x5b,
            'TLOAD': 0x5c,
            'TSTORE': 0x5d,
            'MCOPY': 0x5e,
            'LOG0': 0xa0,
            'LOG1': 0xa1,
            'LOG2': 0xa2,
            'LOG3': 0xa3,
            'LOG4': 0xa4,
            'CREATE': 0xf0,
            'CALL': 0xf1,
            'SECURE_CALL': 0xf2,
            'RETURN': 0xf3,
            'DELEGATECALL': 0xf4,
            'CREATE2': 0xf5,
            'STATICCALL': 0xfa,
            'REVERT': 0xfd,
            'INVALID': 0xfe,
            'SELFDESTRUCT': 0xff,
        }

        for index in range(1, 17):
            self.opcodes[f'DUP{index}'] = 0x7f + index
            self.opcodes[f'SWAP{index}'] = 0x8f + index
        
        self.push_opcodes = {
            0: 0x5f,
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

        # Conservar las instrucciones separadas por línea. Compactar todo a
        # una sola línea hacía que el parser ignorara las instrucciones 2..N.
        return "\n".join(
            line.strip() for line in source_code.splitlines() if line.strip()
        )

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
            if re.fullmatch(r"[-+]?0[xX][0-9a-fA-F]+", arg):
                instruction['args'].append(int(arg, 16))
            elif re.fullmatch(r"[-+]?\d+", arg):
                instruction['args'].append(int(arg))
            else:
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
                if len(instruction['args']) != 1 or not isinstance(instruction['args'][0], str):
                    raise ValueError("LABEL requires exactly one identifier")
                label_name = instruction['args'][0]
                if label_name in labels:
                    raise ValueError(f"Duplicate label: {label_name}")
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
        args = instruction['args']

        if opcode == 'LABEL':
            return 0
        if opcode in self.opcodes:
            if not args:
                return 1
            if opcode not in ('JUMP', 'JUMPI') or len(args) != 1:
                raise ValueError(f"{opcode} does not accept inline arguments")
            return 2 + self._jump_push_size(args[0])
        if opcode.startswith('PUSH'):
            try:
                size = int(opcode[4:])
            except ValueError:
                raise ValueError(f"Invalid PUSH opcode: {opcode}") from None
            if size not in self.push_opcodes:
                raise ValueError(f"Invalid PUSH size: {size}")
            if (size == 0 and args) or (size > 0 and len(args) != 1):
                raise ValueError(f"PUSH{size} has an invalid argument count")
            return 1 + size
        raise ValueError(f"Unknown opcode: {opcode}")

    @staticmethod
    def _jump_push_size(value: Any) -> int:
        if isinstance(value, str):
            # Labels are absolute code offsets. Two bytes cover normal
            # contracts; compilation rejects larger offsets below.
            return 2
        if not isinstance(value, int) or value < 0:
            raise ValueError("Jump target must be a non-negative integer or label")
        return max(1, (value.bit_length() + 7) // 8)

    @staticmethod
    def _resolve_value(value: Any, labels: Dict[str, int]) -> int:
        if isinstance(value, str):
            if value not in labels:
                raise ValueError(f"Unknown label: {value}")
            return labels[value]
        if not isinstance(value, int) or value < 0:
            raise ValueError("Immediate must be a non-negative integer or label")
        return value

    def _encode_push(self, size: int, value: int) -> bytes:
        max_value = (1 << (size * 8)) - 1
        if value > max_value:
            raise ValueError(f"Immediate {value} does not fit in PUSH{size}")
        return bytes([self.push_opcodes[size]]) + value.to_bytes(size, 'big')

    def _compile_instruction(self, instruction: Dict[str, Any], labels: Dict[str, int], pc: int) -> bytes:
        """Compila una instrucción individual"""
        opcode = instruction['opcode']
        args = instruction['args']

        if opcode in self.opcodes:
            if not args:
                return bytes([self.opcodes[opcode]])
            if opcode not in ('JUMP', 'JUMPI') or len(args) != 1:
                raise ValueError(f"{opcode} does not accept inline arguments")
            value = self._resolve_value(args[0], labels)
            size = self._jump_push_size(args[0])
            return self._encode_push(size, value) + bytes([self.opcodes[opcode]])

        if opcode.startswith('PUSH'):
            try:
                size = int(opcode[4:])
            except ValueError:
                raise ValueError(f"Invalid PUSH opcode: {opcode}") from None
            if size not in self.push_opcodes:
                raise ValueError(f"Invalid PUSH size: {size}")
            if size == 0:
                if args:
                    raise ValueError("PUSH0 does not accept an argument")
                return bytes([self.push_opcodes[0]])
            if len(args) != 1:
                raise ValueError(f"PUSH{size} requires exactly one argument")
            value = self._resolve_value(args[0], labels)
            return self._encode_push(size, value)

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
            elif 0x5f <= opcode <= 0x7f:
                # Instrucción PUSH
                size = opcode - 0x5f
                if size == 0:
                    instructions.append("PUSH0")
                    i += 1
                    continue
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
