"""
MSC Network P2P Module
Módulo de red P2P con DHT y descubrimiento de peers
"""

from .p2p_manager import P2PNetworkManager
from .dht_node import DHTNode
from .eclipse_protection import EclipseAttackProtection
from .discovery import DiscoveryProtocol

__all__ = [
    'P2PNetworkManager',
    'DHTNode',
    'EclipseAttackProtection',
    'DiscoveryProtocol'
]
