"""Constant-product DEX primitives with defensive input validation."""

import hashlib
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Tuple


ZERO = Decimal(0)


def _positive(value: Decimal, name: str):
    if not isinstance(value, Decimal) or value <= ZERO or not value.is_finite():
        raise ValueError(f"{name} must be a finite positive Decimal")


@dataclass
class LiquidityPool:
    token0: str
    token1: str
    reserve0: Decimal = ZERO
    reserve1: Decimal = ZERO
    total_supply: Decimal = ZERO
    fee_rate: Decimal = Decimal("0.003")
    price0_cumulative_last: Decimal = ZERO
    price1_cumulative_last: Decimal = ZERO
    block_timestamp_last: int = 0

    def __post_init__(self):
        if not self.token0 or not self.token1 or self.token0 == self.token1:
            raise ValueError("Pool tokens must be distinct")
        if not (ZERO <= self.fee_rate < Decimal(1)):
            raise ValueError("Invalid fee rate")

    def add_liquidity(self, amount0: Decimal, amount1: Decimal) -> Decimal:
        _positive(amount0, "amount0")
        _positive(amount1, "amount1")
        if self.total_supply == ZERO:
            liquidity = (amount0 * amount1).sqrt()
        else:
            if self.reserve0 <= ZERO or self.reserve1 <= ZERO:
                raise ValueError("Pool reserves are inconsistent")
            liquidity = min(
                amount0 * self.total_supply / self.reserve0,
                amount1 * self.total_supply / self.reserve1,
            )
        if liquidity <= ZERO:
            raise ValueError("Liquidity amount is too small")
        self.total_supply += liquidity
        self.reserve0 += amount0
        self.reserve1 += amount1
        self._update_price_oracle()
        return liquidity

    def remove_liquidity(self, liquidity: Decimal) -> Tuple[Decimal, Decimal]:
        _positive(liquidity, "liquidity")
        if self.total_supply <= ZERO or liquidity > self.total_supply:
            raise ValueError("Insufficient liquidity")
        amount0 = liquidity * self.reserve0 / self.total_supply
        amount1 = liquidity * self.reserve1 / self.total_supply
        self.reserve0 -= amount0
        self.reserve1 -= amount1
        self.total_supply -= liquidity
        self._update_price_oracle()
        return amount0, amount1

    def swap(self, amount_in: Decimal, token_in: str) -> Decimal:
        _positive(amount_in, "amount_in")
        if token_in == self.token0:
            reserve_in, reserve_out = self.reserve0, self.reserve1
            token_out = self.token1
        elif token_in == self.token1:
            reserve_in, reserve_out = self.reserve1, self.reserve0
            token_out = self.token0
        else:
            raise ValueError("Token is not part of this pool")
        if reserve_in <= ZERO or reserve_out <= ZERO:
            raise ValueError("Pool has insufficient liquidity")

        amount_in_with_fee = amount_in * (Decimal(1) - self.fee_rate)
        amount_out = amount_in_with_fee * reserve_out / (reserve_in + amount_in_with_fee)
        if amount_out <= ZERO or amount_out >= reserve_out:
            raise ValueError("Invalid swap output")
        if token_out == self.token1:
            self.reserve0 += amount_in
            self.reserve1 -= amount_out
        else:
            self.reserve1 += amount_in
            self.reserve0 -= amount_out
        self._update_price_oracle()
        return amount_out

    def get_price(self, token: str) -> Decimal:
        if self.reserve0 <= ZERO or self.reserve1 <= ZERO:
            raise ValueError("Pool has no liquidity")
        if token == self.token0:
            return self.reserve1 / self.reserve0
        if token == self.token1:
            return self.reserve0 / self.reserve1
        raise ValueError("Token is not part of this pool")

    def _update_price_oracle(self):
        current_timestamp = int(time.time())
        elapsed = current_timestamp - self.block_timestamp_last
        if elapsed > 0 and self.reserve0 > ZERO and self.reserve1 > ZERO:
            self.price0_cumulative_last += self.reserve1 / self.reserve0 * elapsed
            self.price1_cumulative_last += self.reserve0 / self.reserve1 * elapsed
        self.block_timestamp_last = current_timestamp


class DEXProtocol:
    def __init__(self, factory_address: str):
        self.factory_address = factory_address
        self.pairs = {}
        self.router_address = None

    def create_pair(self, token0: str, token1: str) -> str:
        if not token0 or not token1 or token0 == token1:
            raise ValueError("Pair tokens must be distinct")
        if token0 > token1:
            token0, token1 = token1, token0
        pair_address = self._compute_pair_address(token0, token1)
        if pair_address not in self.pairs:
            self.pairs[pair_address] = LiquidityPool(token0, token1)
        return pair_address

    def _compute_pair_address(self, token0: str, token1: str) -> str:
        data = f"{self.factory_address}{token0}{token1}"
        return "0x" + hashlib.sha256(data.encode()).hexdigest()[:40]

    def get_pair(self, token0: str, token1: str) -> LiquidityPool:
        if token0 > token1:
            token0, token1 = token1, token0
        return self.pairs.get(self._compute_pair_address(token0, token1))

    def swap_tokens(self, token_in: str, token_out: str, amount_in: Decimal) -> Decimal:
        if token_in == token_out:
            raise ValueError("Swap tokens must be distinct")
        pair = self.get_pair(token_in, token_out)
        if not pair:
            raise ValueError("Pair does not exist")
        return pair.swap(amount_in, token_in)
