"""
Protocolo de préstamos con liquidaciones
"""

from dataclasses import dataclass
from decimal import Decimal
from collections import defaultdict
from typing import Dict

from ..core.config import BlockchainConfig

@dataclass
class Position:
    """Posición de usuario en un mercado"""
    supplied: Decimal = Decimal(0)
    borrowed: Decimal = Decimal(0)

@dataclass
class Market:
    """Mercado de préstamos para un activo"""
    asset: str
    total_supply: Decimal = Decimal(0)
    total_borrowed: Decimal = Decimal(0)
    collateral_factor: Decimal = Decimal('0.8')  # 80%
    interest_rate: Decimal = Decimal('0.05')  # 5% anual
    last_update: int = 0

    def deposit(self, amount: Decimal) -> Decimal:
        """Deposita activos en el mercado"""
        # Calcular shares basado en total supply
        if self.total_supply == 0:
            shares = amount
        else:
            shares = amount * self.total_supply / (self.total_supply + self.total_borrowed)
        
        self.total_supply += amount
        return shares

    def borrow(self, amount: Decimal):
        """Pide prestado del mercado"""
        if amount > self.total_supply - self.total_borrowed:
            raise ValueError("Insufficient liquidity")
        
        self.total_borrowed += amount

    def repay(self, amount: Decimal):
        """Paga préstamo"""
        if amount > self.total_borrowed:
            amount = self.total_borrowed
        
        self.total_borrowed -= amount

    def get_utilization_rate(self) -> Decimal:
        """Obtiene tasa de utilización del mercado"""
        if self.total_supply == 0:
            return Decimal(0)
        return self.total_borrowed / self.total_supply

class LendingProtocol:
    """Protocolo de préstamos con liquidaciones"""

    def __init__(self):
        self.markets = {}  # asset -> Market
        self.user_positions = defaultdict(dict)  # user -> asset -> Position
        self.oracle = None

    def create_market(self, asset: str, collateral_factor: Decimal):
        """Crea nuevo mercado de préstamos"""
        self.markets[asset] = Market(
            asset=asset,
            collateral_factor=collateral_factor
        )

    def supply(self, user: str, asset: str, amount: Decimal):
        """Usuario deposita activos"""
        if asset not in self.markets:
            raise ValueError("Market does not exist")

        market = self.markets[asset]
        shares = market.deposit(amount)

        if user not in self.user_positions:
            self.user_positions[user] = {}

        if asset not in self.user_positions[user]:
            self.user_positions[user][asset] = Position()

        self.user_positions[user][asset].supplied += shares

    def borrow(self, user: str, asset: str, amount: Decimal):
        """Usuario pide prestado"""
        # Verificar colateral
        if not self._check_collateral(user, asset, amount):
            raise ValueError("Insufficient collateral")

        market = self.markets[asset]
        market.borrow(amount)

        self.user_positions[user][asset].borrowed += amount

    def liquidate(self, liquidator: str, borrower: str, 
                  repay_asset: str, repay_amount: Decimal,
                  collateral_asset: str):
        """Liquida posición insolvente"""
        # Verificar que la posición es liquidable
        if self._health_factor(borrower) >= Decimal('1.0'):
            raise ValueError("Position is healthy")

        # Calcular bonus de liquidación
        liquidation_bonus = repay_amount * Decimal(str(BlockchainConfig.LIQUIDATION_BONUS))
        collateral_to_seize = repay_amount + liquidation_bonus

        # Transferir activos
        # ... implementación de transferencias

    def _check_collateral(self, user: str, asset: str, borrow_amount: Decimal) -> bool:
        """Verifica si usuario tiene suficiente colateral"""
        total_collateral = Decimal(0)
        total_borrowed = Decimal(0)

        for asset, position in self.user_positions[user].items():
            market = self.markets[asset]
            price = self._get_price(asset)

            # Calcular valor del colateral
            collateral_value = position.supplied * price * market.collateral_factor
            total_collateral += collateral_value

            # Calcular valor prestado
            borrowed_value = position.borrowed * price
            total_borrowed += borrowed_value

        # Añadir nuevo préstamo
        new_borrow_value = borrow_amount * self._get_price(asset)
        total_borrowed += new_borrow_value

        return total_collateral >= total_borrowed

    def _health_factor(self, user: str) -> Decimal:
        """Calcula factor de salud de la posición"""
        total_collateral = Decimal(0)
        total_borrowed = Decimal(0)

        for asset, position in self.user_positions[user].items():
            market = self.markets[asset]
            price = self._get_price(asset)

            collateral_value = position.supplied * price * market.collateral_factor
            total_collateral += collateral_value

            borrowed_value = position.borrowed * price
            total_borrowed += borrowed_value

        if total_borrowed == 0:
            return Decimal('inf')

        return total_collateral / total_borrowed

    def _get_price(self, asset: str) -> Decimal:
        """Obtiene precio del activo (placeholder)"""
        # En implementación real, consultaría oracle
        return Decimal('100')  # Precio placeholder
