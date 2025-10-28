"""
Protocolo DEX con AMM avanzado
"""

import hashlib
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Tuple

@dataclass
class LiquidityPool:
    """Pool de liquidez con matemáticas precisas"""
    token0: str
    token1: str
    reserve0: Decimal = Decimal(0)
    reserve1: Decimal = Decimal(0)
    total_supply: Decimal = Decimal(0)
    fee_rate: Decimal = Decimal('0.003')  # 0.3%

    # Price oracle
    price0_cumulative_last: Decimal = Decimal(0)
    price1_cumulative_last: Decimal = Decimal(0)
    block_timestamp_last: int = 0

    def add_liquidity(self, amount0: Decimal, amount1: Decimal) -> Decimal:
        """Añade liquidez al pool"""
        if self.total_supply == 0:
            # Primera liquidez
            liquidity = (amount0 * amount1).sqrt()
            self.total_supply = liquidity
        else:
            # Liquidez proporcional
            liquidity = min(
                amount0 * self.total_supply / self.reserve0,
                amount1 * self.total_supply / self.reserve1
            )
            self.total_supply += liquidity

        self.reserve0 += amount0
        self.reserve1 += amount1
        self._update_price_oracle()

        return liquidity

    def remove_liquidity(self, liquidity: Decimal) -> Tuple[Decimal, Decimal]:
        """Remueve liquidez del pool"""
        if liquidity > self.total_supply:
            raise ValueError("Insufficient liquidity")

        amount0 = liquidity * self.reserve0 / self.total_supply
        amount1 = liquidity * self.reserve1 / self.total_supply

        self.reserve0 -= amount0
        self.reserve1 -= amount1
        self.total_supply -= liquidity
        self._update_price_oracle()

        return amount0, amount1

    def swap(self, amount_in: Decimal, token_in: str) -> Decimal:
        """Intercambia tokens usando x*y=k"""
        if token_in == self.token0:
            reserve_in = self.reserve0
            reserve_out = self.reserve1
        else:
            reserve_in = self.reserve1
            reserve_out = self.reserve0

        # Aplicar fee
        amount_in_with_fee = amount_in * (Decimal(1) - self.fee_rate)

        # Calcular amount out
        amount_out = (amount_in_with_fee * reserve_out) / (reserve_in + amount_in_with_fee)

        # Actualizar reservas
        if token_in == self.token0:
            self.reserve0 += amount_in
            self.reserve1 -= amount_out
        else:
            self.reserve1 += amount_in
            self.reserve0 -= amount_out

        self._update_price_oracle()

        return amount_out

    def get_price(self, token: str) -> Decimal:
        """Obtiene precio spot del token"""
        if token == self.token0:
            return self.reserve1 / self.reserve0
        else:
            return self.reserve0 / self.reserve1

    def _update_price_oracle(self):
        """Actualiza oracle de precio acumulativo"""
        current_timestamp = int(time.time())
        time_elapsed = current_timestamp - self.block_timestamp_last

        if time_elapsed > 0 and self.reserve0 > 0 and self.reserve1 > 0:
            # Actualizar precios acumulativos
            self.price0_cumulative_last += self.reserve1 / self.reserve0 * time_elapsed
            self.price1_cumulative_last += self.reserve0 / self.reserve1 * time_elapsed

        self.block_timestamp_last = current_timestamp

class DEXProtocol:
    """Protocolo DEX mejorado con AMM avanzado"""

    def __init__(self, factory_address: str):
        self.factory_address = factory_address
        self.pairs = {}  # pair_address -> LiquidityPool
        self.router_address = None

    def create_pair(self, token0: str, token1: str) -> str:
        """Crea nuevo par de liquidez"""
        # Ordenar tokens
        if token0 > token1:
            token0, token1 = token1, token0

        pair_address = self._compute_pair_address(token0, token1)

        if pair_address not in self.pairs:
            self.pairs[pair_address] = LiquidityPool(token0, token1)

        return pair_address

    def _compute_pair_address(self, token0: str, token1: str) -> str:
        """Calcula dirección determinística del par"""
        data = f"{self.factory_address}{token0}{token1}"
        return '0x' + hashlib.sha256(data.encode()).hexdigest()[:40]

    def get_pair(self, token0: str, token1: str) -> LiquidityPool:
        """Obtiene pool de liquidez"""
        if token0 > token1:
            token0, token1 = token1, token0
        
        pair_address = self._compute_pair_address(token0, token1)
        return self.pairs.get(pair_address)

    def swap_tokens(self, token_in: str, token_out: str, amount_in: Decimal) -> Decimal:
        """Intercambia tokens a través del DEX"""
        pair = self.get_pair(token_in, token_out)
        if not pair:
            raise ValueError("Pair does not exist")
        
        return pair.swap(amount_in, token_in)
