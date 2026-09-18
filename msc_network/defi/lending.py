"""Collateralized lending primitives with conservative accounting."""

from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from typing import Dict

from ..core.config import BlockchainConfig

ZERO = Decimal(0)


def _positive(value: Decimal, name: str):
    if not isinstance(value, Decimal) or value <= ZERO or not value.is_finite():
        raise ValueError(f"{name} must be a finite positive Decimal")


@dataclass
class Position:
    supplied: Decimal = ZERO
    borrowed: Decimal = ZERO


@dataclass
class Market:
    asset: str
    total_supply: Decimal = ZERO
    total_borrowed: Decimal = ZERO
    collateral_factor: Decimal = Decimal("0.8")
    interest_rate: Decimal = Decimal("0.05")
    last_update: int = 0

    def deposit(self, amount: Decimal) -> Decimal:
        _positive(amount, "amount")
        if self.total_supply == ZERO:
            shares = amount
        else:
            available = self.total_supply + self.total_borrowed
            shares = amount * self.total_supply / available
        self.total_supply += amount
        return shares

    def borrow(self, amount: Decimal):
        _positive(amount, "amount")
        if amount > self.total_supply - self.total_borrowed:
            raise ValueError("Insufficient liquidity")
        self.total_borrowed += amount

    def repay(self, amount: Decimal):
        _positive(amount, "amount")
        self.total_borrowed -= min(amount, self.total_borrowed)

    def get_utilization_rate(self) -> Decimal:
        if self.total_supply == ZERO:
            return ZERO
        return self.total_borrowed / self.total_supply


class LendingProtocol:
    def __init__(self):
        self.markets = {}
        self.user_positions = defaultdict(dict)
        self.oracle = None

    def create_market(self, asset: str, collateral_factor: Decimal):
        if not asset or not isinstance(collateral_factor, Decimal):
            raise ValueError("Invalid market parameters")
        if not collateral_factor.is_finite() or not (ZERO < collateral_factor <= Decimal(1)):
            raise ValueError("Collateral factor must be in (0, 1]")
        self.markets[asset] = Market(asset=asset, collateral_factor=collateral_factor)

    def supply(self, user: str, asset: str, amount: Decimal):
        _positive(amount, "amount")
        if asset not in self.markets:
            raise ValueError("Market does not exist")
        shares = self.markets[asset].deposit(amount)
        self.user_positions[user].setdefault(asset, Position()).supplied += shares

    def borrow(self, user: str, asset: str, amount: Decimal):
        _positive(amount, "amount")
        if asset not in self.markets:
            raise ValueError("Market does not exist")
        if not self._check_collateral(user, asset, amount):
            raise ValueError("Insufficient collateral")
        self.markets[asset].borrow(amount)
        self.user_positions[user].setdefault(asset, Position()).borrowed += amount

    def liquidate(self, liquidator: str, borrower: str, repay_asset: str,
                  repay_amount: Decimal, collateral_asset: str):
        _positive(repay_amount, "repay_amount")
        if repay_asset not in self.markets or collateral_asset not in self.markets:
            raise ValueError("Market does not exist")
        if self._health_factor(borrower) >= Decimal("1.0"):
            raise ValueError("Position is healthy")
        debt = self.user_positions[borrower].get(repay_asset)
        collateral = self.user_positions[borrower].get(collateral_asset)
        if not debt or not collateral or debt.borrowed <= ZERO:
            raise ValueError("Position not liquidatable")

        repay = min(repay_amount, debt.borrowed)
        seize_value = repay * (Decimal(1) + Decimal(str(BlockchainConfig.LIQUIDATION_BONUS)))
        seize_amount = seize_value * self._get_price(repay_asset) / self._get_price(collateral_asset)
        if seize_amount > collateral.supplied:
            seize_amount = collateral.supplied
        debt.borrowed -= repay
        self.markets[repay_asset].repay(repay)
        collateral.supplied -= seize_amount
        return repay, seize_amount

    def _check_collateral(self, user: str, borrow_asset: str, borrow_amount: Decimal) -> bool:
        total_collateral = ZERO
        total_borrowed = ZERO
        for supplied_asset, position in self.user_positions[user].items():
            market = self.markets[supplied_asset]
            price = self._get_price(supplied_asset)
            total_collateral += position.supplied * price * market.collateral_factor
            total_borrowed += position.borrowed * price
        total_borrowed += borrow_amount * self._get_price(borrow_asset)
        return total_collateral >= total_borrowed

    def _health_factor(self, user: str) -> Decimal:
        total_collateral = ZERO
        total_borrowed = ZERO
        for asset, position in self.user_positions[user].items():
            market = self.markets[asset]
            price = self._get_price(asset)
            total_collateral += position.supplied * price * market.collateral_factor
            total_borrowed += position.borrowed * price
        if total_borrowed == ZERO:
            return Decimal("inf")
        return total_collateral / total_borrowed

    def _get_price(self, asset: str) -> Decimal:
        if self.oracle is None:
            raise ValueError("Price oracle is not configured")
        price = self.oracle.get_price(asset)
        if price is None or not price.is_finite() or price <= ZERO:
            raise ValueError("Asset price unavailable")
        return price
