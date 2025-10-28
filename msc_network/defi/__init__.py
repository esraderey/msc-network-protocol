"""
MSC Network DeFi Module
Módulo de protocolos DeFi (DEX, Lending, etc.)
"""

from .dex import DEXProtocol, LiquidityPool
from .lending import LendingProtocol, Market, Position
from .oracle import OracleSystem

__all__ = [
    'DEXProtocol',
    'LiquidityPool',
    'LendingProtocol',
    'Market',
    'Position',
    'OracleSystem'
]
