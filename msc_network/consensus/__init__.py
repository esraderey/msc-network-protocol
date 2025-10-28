"""
MSC Network Consensus Module
Módulo de consenso híbrido PoW/PoS con VRF
"""

from .vrf import VRF
from .validator_registry import ValidatorRegistry
from .hybrid_consensus import HybridConsensus

__all__ = [
    'VRF',
    'ValidatorRegistry', 
    'HybridConsensus'
]
