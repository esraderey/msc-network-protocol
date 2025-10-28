"""
Sistema de staking con delegación
"""

import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Dict, Any
from enum import Enum
from collections import defaultdict

from ..core.config import BlockchainConfig

@dataclass
class ValidatorInfo:
    """Información del validador"""
    address: str
    commission_rate: Decimal
    min_self_delegation: Decimal
    self_delegation: Decimal
    total_delegation: Decimal
    status: 'ValidatorStatus'

class ValidatorStatus(Enum):
    """Estado del validador"""
    INACTIVE = "inactive"
    ACTIVE = "active"
    JAILED = "jailed"
    UNBONDING = "unbonding"

@dataclass
class UnbondingEntry:
    """Entrada de unbonding"""
    delegator: str
    validator: str
    amount: Decimal
    completion_time: float

class StakingSystem:
    """Sistema de staking con delegación"""

    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.validators = {}  # address -> ValidatorInfo
        self.delegations = defaultdict(dict)  # delegator -> validator -> amount
        self.rewards_pool = Decimal(0)
        self.unbonding_period = 7 * 24 * 3600  # 7 días
        self.unbonding_entries = []  # Lista de unbonding entries

    def register_validator(self, address: str, commission_rate: Decimal, 
                          min_self_delegation: Decimal):
        """Registra nuevo validador"""
        if commission_rate > Decimal('0.2'):  # Max 20%
            raise ValueError("Commission rate too high")

        self.validators[address] = ValidatorInfo(
            address=address,
            commission_rate=commission_rate,
            min_self_delegation=min_self_delegation,
            self_delegation=Decimal(0),
            total_delegation=Decimal(0),
            status=ValidatorStatus.INACTIVE
        )

    def delegate(self, delegator: str, validator: str, amount: Decimal):
        """Delega stake a validador"""
        if validator not in self.validators:
            raise ValueError("Validator does not exist")

        # Actualizar delegación
        self.delegations[delegator][validator] = \
            self.delegations[delegator].get(validator, Decimal(0)) + amount

        # Actualizar totales del validador
        validator_info = self.validators[validator]
        validator_info.total_delegation += amount

        if delegator == validator:
            validator_info.self_delegation += amount

        # Activar validador si cumple requisitos
        if validator_info.self_delegation >= validator_info.min_self_delegation and \
           validator_info.total_delegation >= BlockchainConfig.MIN_STAKE_AMOUNT * 10**18:
            validator_info.status = ValidatorStatus.ACTIVE

    def undelegate(self, delegator: str, validator: str, amount: Decimal):
        """Inicia proceso de undelegation"""
        if validator not in self.delegations[delegator]:
            raise ValueError("No delegation found")

        current_delegation = self.delegations[delegator][validator]
        if amount > current_delegation:
            raise ValueError("Insufficient delegation")

        # Crear unbonding entry
        unbonding_entry = UnbondingEntry(
            delegator=delegator,
            validator=validator,
            amount=amount,
            completion_time=time.time() + self.unbonding_period
        )

        # Actualizar delegaciones
        self.delegations[delegator][validator] -= amount
        self.validators[validator].total_delegation -= amount

        if delegator == validator:
            self.validators[validator].self_delegation -= amount

        # Añadir a lista de unbonding
        self.unbonding_entries.append(unbonding_entry)

        return unbonding_entry

    def complete_unbonding(self, delegator: str, validator: str) -> Decimal:
        """Completa proceso de unbonding y devuelve tokens"""
        current_time = time.time()
        completed_entries = []
        total_amount = Decimal(0)

        for entry in self.unbonding_entries:
            if (entry.delegator == delegator and 
                entry.validator == validator and 
                entry.completion_time <= current_time):
                completed_entries.append(entry)
                total_amount += entry.amount

        # Remover entradas completadas
        for entry in completed_entries:
            self.unbonding_entries.remove(entry)

        return total_amount

    def distribute_rewards(self, block_rewards: Dict[str, Decimal]):
        """Distribuye recompensas a validadores y delegadores"""
        for validator_address, reward in block_rewards.items():
            if validator_address not in self.validators:
                continue

            validator = self.validators[validator_address]

            # Calcular comisión del validador
            commission = reward * validator.commission_rate
            validator_reward = commission

            # Recompensas para delegadores
            delegator_rewards = reward - commission

            # Distribuir proporcionalmente
            for delegator, delegation in self.delegations.items():
                if validator_address in delegation:
                    delegator_share = delegation[validator_address] / validator.total_delegation
                    delegator_reward = delegator_rewards * delegator_share

                    # Añadir recompensa (simplificado)
                    # En implementación real, se acumularían para reclamar
                    self.rewards_pool += delegator_reward

    def get_validator_info(self, address: str) -> ValidatorInfo:
        """Obtiene información de un validador"""
        if address not in self.validators:
            raise ValueError("Validator does not exist")
        return self.validators[address]

    def get_all_validators(self) -> List[ValidatorInfo]:
        """Obtiene todos los validadores"""
        return list(self.validators.values())

    def get_active_validators(self) -> List[ValidatorInfo]:
        """Obtiene validadores activos"""
        return [v for v in self.validators.values() if v.status == ValidatorStatus.ACTIVE]

    def get_delegations(self, delegator: str) -> Dict[str, Decimal]:
        """Obtiene delegaciones de un usuario"""
        return dict(self.delegations[delegator])

    def get_validator_delegations(self, validator: str) -> Dict[str, Decimal]:
        """Obtiene delegaciones a un validador"""
        delegations = {}
        for delegator, validator_delegations in self.delegations.items():
            if validator in validator_delegations:
                delegations[delegator] = validator_delegations[validator]
        return delegations

    def get_staking_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas de staking"""
        total_validators = len(self.validators)
        active_validators = len(self.get_active_validators())
        total_delegations = sum(
            sum(delegations.values()) 
            for delegations in self.delegations.values()
        )
        pending_unbonding = len(self.unbonding_entries)

        return {
            'total_validators': total_validators,
            'active_validators': active_validators,
            'total_delegations': float(total_delegations),
            'rewards_pool': float(self.rewards_pool),
            'pending_unbonding': pending_unbonding,
            'unbonding_period': self.unbonding_period
        }

    def cleanup_completed_unbonding(self):
        """Limpia entradas de unbonding completadas"""
        current_time = time.time()
        self.unbonding_entries = [
            entry for entry in self.unbonding_entries
            if entry.completion_time > current_time
        ]
