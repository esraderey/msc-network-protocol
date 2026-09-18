"""
Protocolo de descubrimiento de peers mejorado
"""

import asyncio
import time
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class DiscoveryProtocol:
    """Protocolo de descubrimiento de peers con múltiples estrategias"""
    
    def __init__(self, node_id: str, listen_address: tuple):
        self.node_id = node_id
        self.listen_address = listen_address
        self.seed_nodes = []
        self.bootstrap_nodes = []
        self.discovered_peers = set()
        self.connected_peers = {}
        self.peer_reputation = {}
        self.discovery_interval = 30
        self.last_discovery = 0
        
        # Configuración de red
        self.external_ip = None
        self.external_port = None
        self.nat_type = "unknown"
        
        # Estadísticas
        self.stats = {
            'discovery_attempts': 0,
            'successful_discoveries': 0,
            'connection_attempts': 0,
            'successful_connections': 0
        }
    
    def add_seed_node(self, address: str):
        """Añade nodo semilla"""
        self.seed_nodes.append(address)
    
    def add_bootstrap_node(self, address: str):
        """Añade nodo bootstrap"""
        self.bootstrap_nodes.append(address)
    
    async def start(self):
        """Inicia protocolo de descubrimiento con múltiples estrategias"""
        logger.info("Starting enhanced peer discovery protocol")
        
        # Detectar NAT y configuración de red
        asyncio.create_task(self._detect_nat())
        
        # Conectar a nodos semilla (alta prioridad)
        for seed_node in self.seed_nodes:
            asyncio.create_task(self._connect_with_retry(seed_node, is_seed=True))
        
        # Conectar a nodos bootstrap
        bootstrap_tasks = []
        for boot_node in self.bootstrap_nodes:
            task = asyncio.create_task(self._connect_with_retry(boot_node))
            bootstrap_tasks.append(task)
        
        # Esperar a que al menos un nodo bootstrap se conecte
        try:
            await asyncio.wait_for(asyncio.gather(*bootstrap_tasks, return_exceptions=True), 
                                  timeout=30)
        except asyncio.TimeoutError:
            logger.warning("Timeout connecting to bootstrap nodes")
        
        # Iniciar descubrimiento periódico
        asyncio.create_task(self._periodic_discovery())
        
        # Iniciar mantenimiento de peers
        asyncio.create_task(self._peer_maintenance())
        
        logger.info("Peer discovery protocol started")
    
    async def _detect_nat(self):
        """Detecta tipo de NAT y dirección IP externa"""
        try:
            # Intentar obtener IP externa de servicios STUN
            stun_servers = [
                "stun.l.google.com:19302",
                "stun1.l.google.com:19302",
                "stun2.l.google.com:19302"
            ]
            
            # Implementación simplificada - en producción usar librería STUN
            for server in stun_servers:
                try:
                    # Simular detección STUN
                    response = await asyncio.wait_for(
                        self._query_stun_server(server), 
                        timeout=5
                    )
                    if response:
                        self.external_ip = response.get('ip')
                        self.external_port = response.get('port')
                        self.nat_type = response.get('nat_type', 'unknown')
                        logger.info(f"NAT detection: {self.nat_type}, External IP: {self.external_ip}:{self.external_port}")
                        break
                except:
                    continue
            
            if not self.external_ip:
                logger.warning("External address could not be verified; NAT remains unknown")
        except Exception as e:
            logger.error(f"Error in NAT detection: {e}")
    
    async def _query_stun_server(self, server):
        """Consulta servidor STUN para obtener información de NAT"""
        raise NotImplementedError("STUN discovery requires a STUN client implementation")

    @staticmethod
    def _parse_address(address: str) -> tuple:
        if not isinstance(address, str) or not address.strip():
            raise ValueError("peer address must be host:port")
        value = address.strip()
        if value.startswith('['):
            host, separator, port = value.partition(']:')
            host = host[1:]
        else:
            host, separator, port = value.rpartition(':')
        if not separator or not host or not port.isdigit():
            raise ValueError("peer address must be host:port")
        port_number = int(port)
        if not 1 <= port_number <= 65535:
            raise ValueError("peer port must be between 1 and 65535")
        return host, port_number
    
    async def _connect_with_retry(self, address: str, max_retries=3, is_seed=False):
        """Conecta a un peer con reintentos"""
        retries = 0
        backoff = 1
        
        while retries < max_retries:
            try:
                self.stats['connection_attempts'] += 1
                await self.connect_to_peer(address)
                self.stats['successful_connections'] += 1
                
                # Actualizar reputación positivamente
                self._update_peer_reputation(address, 5)
                
                # Si es un nodo semilla, mantener en la lista para reconexión
                if is_seed:
                    logger.info(f"Successfully connected to seed node {address}")
                
                return True
                
            except Exception as e:
                retries += 1
                logger.warning(f"Connection attempt {retries} failed for {address}: {e}")
                
                if retries < max_retries:
                    await asyncio.sleep(backoff)
                    backoff *= 2  # Backoff exponencial
                else:
                    # Actualizar reputación negativamente
                    self._update_peer_reputation(address, -2)
                    logger.error(f"Failed to connect to {address} after {max_retries} attempts")
        
        return False
    
    async def connect_to_peer(self, address: str):
        """Verifica una conexión TCP real con un peer."""
        host, port = self._parse_address(address)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=5
        )
        writer.write((f'{{"type":"hello","node_id":"{self.node_id}"}}\n').encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        self.connected_peers[address] = {'address': (host, port), 'last_seen': time.time()}
        self.discovered_peers.add(address)
    
    async def _periodic_discovery(self):
        """Descubrimiento periódico de peers"""
        while True:
            try:
                await self._discover_new_peers()
                await asyncio.sleep(self.discovery_interval)
            except Exception as e:
                logger.error(f"Error in periodic discovery: {e}")
                await asyncio.sleep(60)  # Esperar más tiempo en caso de error
    
    async def _discover_new_peers(self):
        """Descubre nuevos peers usando múltiples estrategias"""
        self.stats['discovery_attempts'] += 1
        
        # Estrategia 1: Consultar nodos conocidos
        await self._query_known_peers()
        
        # Estrategia 2: DNS discovery
        await self._dns_discovery()
        
        # Estrategia 3: Random walk
        await self._random_walk_discovery()
        
        self.stats['successful_discoveries'] += 1
        self.last_discovery = time.time()
    
    async def _query_known_peers(self):
        """No añade peers sin una respuesta firmada del protocolo DHT."""
        return []
    
    async def _dns_discovery(self):
        """DNS discovery requiere un dominio de semillas configurado."""
        return []
    
    async def _random_walk_discovery(self):
        """Random walk requiere peers DHT conectados y un protocolo FIND_NODE."""
        return []
    
    async def _peer_maintenance(self):
        """Mantenimiento de peers conectados"""
        while True:
            try:
                await self._ping_peers()
                await self._cleanup_stale_peers()
                await asyncio.sleep(60)  # Cada minuto
            except Exception as e:
                logger.error(f"Error in peer maintenance: {e}")
                await asyncio.sleep(60)
    
    async def _ping_peers(self):
        """Comprueba conectividad TCP y elimina entradas que fallan."""
        stale = []
        for address in list(self.connected_peers):
            try:
                host, port = self._parse_address(address)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=5
                )
                writer.write((f'{{"type":"ping","node_id":"{self.node_id}"}}\n').encode())
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                self.connected_peers[address]['last_seen'] = time.time()
                self._update_peer_reputation(address, 1)
            except (OSError, asyncio.TimeoutError, ValueError):
                stale.append(address)
                self._update_peer_reputation(address, -5)
        for address in stale:
            self.connected_peers.pop(address, None)
    
    async def _cleanup_stale_peers(self):
        """Elimina peers que no han respondido durante dos intervalos."""
        cutoff = time.time() - max(60, self.discovery_interval * 2)
        for address, info in list(self.connected_peers.items()):
            if info.get('last_seen', 0) < cutoff:
                self.connected_peers.pop(address, None)
    
    def _update_peer_reputation(self, peer_id: str, change: int):
        """Actualiza reputación de un peer"""
        if peer_id not in self.peer_reputation:
            self.peer_reputation[peer_id] = 50  # Reputación inicial
        
        self.peer_reputation[peer_id] = max(0, min(100, 
            self.peer_reputation[peer_id] + change))
    
    def get_discovery_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas de descubrimiento"""
        return {
            'node_id': self.node_id,
            'listen_address': self.listen_address,
            'external_ip': self.external_ip,
            'external_port': self.external_port,
            'nat_type': self.nat_type,
            'seed_nodes': len(self.seed_nodes),
            'bootstrap_nodes': len(self.bootstrap_nodes),
            'discovered_peers': len(self.discovered_peers),
            'last_discovery': self.last_discovery,
            'stats': self.stats
        }
