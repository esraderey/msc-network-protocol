"""
Registro de validadores con stake y reputación
"""

from typing import List, Dict, Any

class ValidatorRegistry:
    """Registro de validadores con stake y reputación"""
    
    def __init__(self):
        self.validators = {}  # address -> ValidatorInfo
        self.total_stake = 0
        self.min_stake = 1000000  # Stake mínimo para ser validador
    
    def register_validator(self, address: str, stake: int, public_key: bytes):
        """Registra un validador"""
        if stake < self.min_stake:
            raise ValueError("Stake insuficiente para ser validador")
        
        self.validators[address] = {
            'stake': stake,
            'public_key': public_key,
            'reputation': 100,  # Reputación inicial
            'slashing_count': 0,
            'last_selected': 0,
            'performance_score': 1.0
        }
        self.total_stake += stake
    
    def update_stake(self, address: str, new_stake: int):
        """Actualiza stake de validador"""
        if address not in self.validators:
            raise ValueError("Validador no registrado")
        
        old_stake = self.validators[address]['stake']
        self.validators[address]['stake'] = new_stake
        self.total_stake += (new_stake - old_stake)
    
    def slash_validator(self, address: str, slashing_amount: int):
        """Penaliza validador por comportamiento malicioso"""
        if address not in self.validators:
            return
        
        validator = self.validators[address]
        slashed_stake = min(slashing_amount, validator['stake'])
        
        validator['stake'] -= slashed_stake
        validator['slashing_count'] += 1
        validator['reputation'] = max(0, validator['reputation'] - 10)
        validator['performance_score'] *= 0.9
        
        self.total_stake -= slashed_stake
    
    def get_weighted_validators(self) -> List[tuple]:
        """Obtiene lista de validadores con pesos"""
        weighted_validators = []
        
        for address, info in self.validators.items():
            if info['stake'] >= self.min_stake:
                # Peso basado en stake, reputación y performance
                weight = (info['stake'] * info['reputation'] * info['performance_score']) / 10000
                weighted_validators.append((address, weight, info))
        
        return sorted(weighted_validators, key=lambda x: x[1], reverse=True)
