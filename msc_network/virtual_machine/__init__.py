"""
MSC Network Virtual Machine Module
Módulo de máquina virtual para smart contracts
"""

from .vm import MSCVirtualMachine
from .compiler import MSCCompiler

__all__ = [
    'MSCVirtualMachine',
    'MSCCompiler'
]
