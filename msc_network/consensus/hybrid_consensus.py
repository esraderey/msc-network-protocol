"""
Sistema de consenso híbrido PoW/PoS con VRF y selección segura
"""

import hashlib
from typing import List, Dict, Any

from .vrf import VRF
from .validator_registry import ValidatorRegistry

class HybridConsensus:
    """Sistema de consenso híbrido PoW/PoS con VRF y selección segura"""
    
    def __init__(self):
        self.pow_pos_ratio = 10  # Cada 10 bloques, 1 PoS
        self.validator_registry = ValidatorRegistry()
        self.vrf_instances = {}  # address -> VRF instance
        self.epoch_length = 100  # Bloques por época
        self.current_epoch = 0
        self.epoch_seed = b""
        
    def register_validator(self, address: str, stake: int, private_key: bytes):
        """Registra validador con clave privada para VRF"""
        public_key = hashlib.sha256(private_key).digest()
        self.validator_registry.register_validator(address, stake, public_key)
        
        # Crear instancia VRF para el validador
        self.vrf_instances[address] = VRF(private_key)
    
    def select_block_producer(self, block_height: int, block_hash: bytes) -> str:
        """Selecciona productor de bloque usando VRF y pesos"""
        if block_height % self.pow_pos_ratio == 0:
            return self._select_pos_validator(block_height, block_hash)
        else:
            return self._select_pow_miner(block_height, block_hash)
    
    def _select_pos_validator(self, block_height: int, block_hash: bytes) -> str:
        """Selecciona validador PoS usando VRF"""
        # Actualizar época si es necesario
        if block_height // self.epoch_length > self.current_epoch:
            self.current_epoch = block_height // self.epoch_length
            self.epoch_seed = block_hash
        
        # Obtener validadores elegibles
        weighted_validators = self.validator_registry.get_weighted_validators()
        
        if not weighted_validators:
            return "POW"  # Fallback a PoW si no hay validadores
        
        # Crear entrada para VRF (combinar altura, hash y época)
        vrf_input = block_hash + block_height.to_bytes(8, 'big') + self.epoch_seed
        
        # Calcular total de pesos
        total_weight = sum(weight for _, weight, _ in weighted_validators)
        
        if total_weight == 0:
            return "POW"
        
        # Generar número aleatorio usando VRF del validador con mayor peso
        primary_validator = weighted_validators[0]
        primary_address = primary_validator[0]
        
        if primary_address in self.vrf_instances:
            vrf_output, vrf_proof = self.vrf_instances[primary_address].generate_proof(vrf_input)
            
            # Convertir output VRF a número
            random_value = int.from_bytes(vrf_output, 'big')
            
            # Seleccionar validador usando distribución ponderada
            selected_validator = self._weighted_random_selection(weighted_validators, random_value, total_weight)
            
            # Verificar que el validador seleccionado puede producir bloque
            if self._can_produce_block(selected_validator, block_height):
                return selected_validator
            else:
                # Fallback a siguiente validador
                return self._select_fallback_validator(weighted_validators, vrf_input)
        
        return "POW"
    
    def _weighted_random_selection(self, weighted_validators: List[tuple], random_value: int, total_weight: int) -> str:
        """Selecciona validador usando distribución ponderada"""
        target = random_value % total_weight
        cumulative_weight = 0
        
        for address, weight, _ in weighted_validators:
            cumulative_weight += weight
            if cumulative_weight > target:
                return address
        
        # Fallback al último validador
        return weighted_validators[-1][0]
    
    def _can_produce_block(self, validator_address: str, block_height: int) -> bool:
        """Verifica si validador puede producir bloque"""
        if validator_address not in self.validator_registry.validators:
            return False
        
        validator = self.validator_registry.validators[validator_address]
        
        # Verificar stake mínimo
        if validator['stake'] < self.validator_registry.min_stake:
            return False
        
        # Verificar reputación mínima
        if validator['reputation'] < 50:
            return False
        
        # Verificar que no ha sido seleccionado recientemente
        if block_height - validator['last_selected'] < 2:
            return False
        
        return True
    
    def _select_fallback_validator(self, weighted_validators: List[tuple], vrf_input: bytes) -> str:
        """Selecciona validador de respaldo"""
        # Implementación simplificada - seleccionar el siguiente en la lista
        if len(weighted_validators) > 1:
            return weighted_validators[1][0]
        return "POW"
    
    def _select_pow_miner(self, block_height: int, block_hash: bytes) -> str:
        """Selecciona minero PoW (placeholder)"""
        return "POW"
    
    def update_validator_performance(self, validator_address: str, success: bool):
        """Actualiza performance de validador"""
        if validator_address not in self.validator_registry.validators:
            return
        
        validator = self.validator_registry.validators[validator_address]
        
        if success:
            validator['performance_score'] = min(1.0, validator['performance_score'] + 0.01)
            validator['reputation'] = min(100, validator['reputation'] + 1)
        else:
            validator['performance_score'] = max(0.1, validator['performance_score'] - 0.05)
            validator['reputation'] = max(0, validator['reputation'] - 5)
    
    def get_consensus_info(self) -> Dict[str, Any]:
        """Obtiene información del consenso"""
        return {
            'total_validators': len(self.validator_registry.validators),
            'total_stake': self.validator_registry.total_stake,
            'current_epoch': self.current_epoch,
            'pow_pos_ratio': self.pow_pos_ratio
        }
