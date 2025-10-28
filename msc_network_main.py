#!/usr/bin/env python3
"""
MSC Network v3.0 - Enterprise-Grade DeFi Platform
Blockchain de próxima generación con consenso híbrido, DeFi avanzado y escalabilidad
Basado en el MSC Framework v5.0

Este es el archivo principal que reemplaza mscnet_blockchain.py
"""

import asyncio
import logging
import time
from typing import Dict, Any

# Importar todos los módulos de MSC Network
from msc_network import (
    MSCBlockchainV3,
    BlockchainConfig,
    P2PNetworkManager,
    HybridConsensus,
    DEXProtocol,
    LendingProtocol,
    OracleSystem,
    MSCVirtualMachine,
    GovernanceSystem,
    StakingSystem
)

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MSCNetworkV3:
    """Clase principal que coordina todos los módulos de MSC Network v3.0"""
    
    def __init__(self, node_id: str = None, listen_address: tuple = None):
        # Generar ID de nodo si no se proporciona
        if not node_id:
            import secrets
            node_id = f"0x{secrets.token_hex(20)}"
        
        if not listen_address:
            listen_address = ("0.0.0.0", BlockchainConfig.DEFAULT_PORT)
        
        # Inicializar blockchain principal
        self.blockchain = MSCBlockchainV3()
        
        # Inicializar módulos
        self.network_manager = P2PNetworkManager(node_id, listen_address)
        self.consensus = HybridConsensus()
        self.dex = DEXProtocol("0x" + "0" * 40)
        self.lending = LendingProtocol()
        self.oracle = OracleSystem()
        self.vm = MSCVirtualMachine(self.blockchain.state_db)
        self.governance = GovernanceSystem("0x" + "0" * 40)
        self.staking = StakingSystem(self.blockchain)
        
        # Estado del nodo
        self.is_running = False
        self.start_time = None
        
        logger.info(f"MSC Network v3.0 initialized with node ID: {node_id}")
    
    async def start(self):
        """Inicia todos los servicios del nodo"""
        if self.is_running:
            logger.warning("Node is already running")
            return
        
        logger.info("Starting MSC Network v3.0...")
        
        try:
            # Iniciar servicios en paralelo
            tasks = [
                self._start_network(),
                self._start_oracle(),
                self._start_consensus(),
                self._start_governance()
            ]
            
            await asyncio.gather(*tasks, return_exceptions=True)
            
            self.is_running = True
            self.start_time = time.time()
            
            logger.info("MSC Network v3.0 started successfully")
            
        except Exception as e:
            logger.error(f"Error starting MSC Network: {e}")
            raise
    
    async def stop(self):
        """Detiene todos los servicios del nodo"""
        if not self.is_running:
            logger.warning("Node is not running")
            return
        
        logger.info("Stopping MSC Network v3.0...")
        
        self.is_running = False
        
        # Detener servicios
        # (Implementación simplificada)
        
        logger.info("MSC Network v3.0 stopped")
    
    async def _start_network(self):
        """Inicia servicios de red"""
        logger.info("Starting network services...")
        # Implementación placeholder
        await asyncio.sleep(0.1)
        logger.info("Network services started")
    
    async def _start_oracle(self):
        """Inicia sistema de oracle"""
        logger.info("Starting oracle system...")
        await self.oracle.start_price_updates()
        logger.info("Oracle system started")
    
    async def _start_consensus(self):
        """Inicia sistema de consenso"""
        logger.info("Starting consensus system...")
        # Implementación placeholder
        await asyncio.sleep(0.1)
        logger.info("Consensus system started")
    
    async def _start_governance(self):
        """Inicia sistema de gobernanza"""
        logger.info("Starting governance system...")
        # Implementación placeholder
        await asyncio.sleep(0.1)
        logger.info("Governance system started")
    
    def get_node_info(self) -> Dict[str, Any]:
        """Obtiene información del nodo"""
        uptime = time.time() - self.start_time if self.start_time else 0
        
        return {
            'version': '3.0.0',
            'node_id': self.network_manager.node_id,
            'listen_address': self.network_manager.listen_address,
            'is_running': self.is_running,
            'uptime': uptime,
            'blockchain_height': len(self.blockchain.chain),
            'network_info': self.network_manager.get_network_info(),
            'consensus_info': self.consensus.get_consensus_info(),
            'staking_stats': self.staking.get_staking_stats(),
            'governance_stats': self.governance.get_governance_stats()
        }
    
    async def mine_block(self, miner_address: str = None):
        """Mina un nuevo bloque"""
        if not miner_address:
            miner_address = self.network_manager.node_id
        
        return await self.blockchain.mine_block(miner_address)
    
    async def add_transaction(self, transaction):
        """Añade una transacción al pool"""
        return await self.blockchain.add_transaction(transaction)

async def main():
    """Función principal"""
    # Crear instancia del nodo
    node = MSCNetworkV3()
    
    try:
        # Iniciar el nodo
        await node.start()
        
        # Mostrar información del nodo
        info = node.get_node_info()
        print(f"\n=== MSC Network v3.0 ===")
        print(f"Node ID: {info['node_id']}")
        print(f"Listen Address: {info['listen_address']}")
        print(f"Status: {'Running' if info['is_running'] else 'Stopped'}")
        print(f"Blockchain Height: {info['blockchain_height']}")
        print(f"Connected Peers: {info['network_info']['connected_peers']}")
        print(f"Validators: {info['consensus_info']['total_validators']}")
        print(f"Active Validators: {info['staking_stats']['active_validators']}")
        print(f"Proposals: {info['governance_stats']['total_proposals']}")
        print("========================\n")
        
        # Mantener el nodo corriendo
        while node.is_running:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    except Exception as e:
        logger.error(f"Error in main: {e}")
    finally:
        await node.stop()

if __name__ == "__main__":
    asyncio.run(main())
