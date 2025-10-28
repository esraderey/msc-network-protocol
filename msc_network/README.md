# MSC Network v3.0 - Estructura Modular

Este directorio contiene la implementación modular de MSC Network v3.0, refactorizada desde el archivo monolítico `mscnet_blockchain.py`.

## Estructura de Módulos

### 📁 core/
Módulo principal que contiene las estructuras de datos fundamentales del blockchain.

**Archivos:**
- `config.py` - Configuración del blockchain
- `types.py` - Tipos y enumeraciones
- `data_structures.py` - Estructuras de datos básicas
- `merkle_trie.py` - Implementación de Merkle Patricia Trie
- `transaction.py` - Clase Transaction
- `block.py` - Clases Block y BlockHeader
- `blockchain.py` - Clase principal MSCBlockchainV3

**Clases principales:**
- `BlockchainConfig` - Configuración del blockchain
- `Transaction` - Transacciones del blockchain
- `Block` - Bloques del blockchain
- `MSCBlockchainV3` - Clase principal del blockchain

### 📁 consensus/
Módulo de consenso híbrido PoW/PoS con VRF.

**Archivos:**
- `vrf.py` - Verifiable Random Function
- `validator_registry.py` - Registro de validadores
- `hybrid_consensus.py` - Sistema de consenso híbrido

**Clases principales:**
- `VRF` - Función aleatoria verificable
- `ValidatorRegistry` - Registro de validadores
- `HybridConsensus` - Consenso híbrido PoW/PoS

### 📁 defi/
Módulo de protocolos DeFi (DEX, Lending, Oracle).

**Archivos:**
- `dex.py` - Protocolo DEX con AMM
- `lending.py` - Protocolo de préstamos
- `oracle.py` - Sistema de Oracle

**Clases principales:**
- `DEXProtocol` - Protocolo de intercambio descentralizado
- `LiquidityPool` - Pool de liquidez
- `LendingProtocol` - Protocolo de préstamos
- `OracleSystem` - Sistema de Oracle

### 📁 network/
Módulo de red P2P con DHT y descubrimiento de peers.

**Archivos:**
- `p2p_manager.py` - Gestor de red P2P
- `dht_node.py` - Nodo DHT
- `eclipse_protection.py` - Protección contra ataques de eclipse
- `discovery.py` - Protocolo de descubrimiento

**Clases principales:**
- `P2PNetworkManager` - Gestor de red P2P
- `DHTNode` - Nodo DHT
- `EclipseAttackProtection` - Protección contra eclipse
- `DiscoveryProtocol` - Descubrimiento de peers

### 📁 virtual_machine/
Módulo de máquina virtual para smart contracts.

**Archivos:**
- `vm.py` - Máquina virtual MSC
- `compiler.py` - Compilador MSC

**Clases principales:**
- `MSCVirtualMachine` - Máquina virtual
- `MSCCompiler` - Compilador de smart contracts

### 📁 governance/
Módulo de gobernanza y staking.

**Archivos:**
- `governance_system.py` - Sistema de gobernanza
- `staking_system.py` - Sistema de staking

**Clases principales:**
- `GovernanceSystem` - Sistema de gobernanza
- `StakingSystem` - Sistema de staking
- `Proposal` - Propuestas de gobernanza
- `ValidatorInfo` - Información de validadores

## Archivos de Utilidades

### 📄 utils.py
Utilidades compartidas para todos los módulos:
- Funciones de codificación RLP
- Funciones de hash (SHA3, Keccak)
- Conversiones de unidades (wei, ether, etc.)
- Validación de direcciones
- Cálculo de Merkle root
- Generación de direcciones aleatorias

## Uso

### Importación básica
```python
from msc_network import MSCBlockchainV3, BlockchainConfig
```

### Uso del archivo principal
```python
# Usar el archivo principal refactorizado
python msc_network_main.py
```

### Uso modular
```python
# Importar módulos específicos
from msc_network.core import Transaction, Block
from msc_network.consensus import HybridConsensus
from msc_network.defi import DEXProtocol
```

## Ventajas de la Refactorización

1. **Modularidad**: Cada módulo tiene una responsabilidad específica
2. **Mantenibilidad**: Código más fácil de mantener y actualizar
3. **Testabilidad**: Cada módulo puede ser probado independientemente
4. **Escalabilidad**: Fácil añadir nuevas funcionalidades
5. **Reutilización**: Los módulos pueden ser reutilizados en otros proyectos
6. **Legibilidad**: Código más organizado y fácil de entender

## Migración desde mscnet_blockchain.py

El archivo original `mscnet_blockchain.py` ha sido refactorizado en estos módulos. Para migrar código existente:

1. Reemplazar importaciones del archivo original por importaciones de módulos específicos
2. Usar `msc_network_main.py` como punto de entrada principal
3. Aprovechar la modularidad para importar solo las funcionalidades necesarias

## Próximos Pasos

1. Añadir tests unitarios para cada módulo
2. Implementar logging avanzado
3. Añadir documentación detallada de APIs
4. Optimizar rendimiento de módulos críticos
5. Implementar métricas y monitoreo
