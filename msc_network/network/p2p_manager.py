"""
Gestor de red P2P con DHT y protección contra eclipse
"""

import time
import random
from typing import List, Dict, Any, Tuple

from .dht_node import DHTNode
from .eclipse_protection import EclipseAttackProtection

class P2PNetworkManager:
    """Gestor de red P2P con DHT y protección contra eclipse"""
    
    def __init__(self, node_id: str, listen_address: tuple):
        self.node_id = node_id
        self.listen_address = listen_address
        self.dht_node = DHTNode(node_id, listen_address)
        self.eclipse_protection = EclipseAttackProtection()
        self.connected_peers = {}  # peer_id -> connection_info
        self.bootstrap_nodes = []
        self.max_peers = 50
        self.discovery_interval = 300  # 5 minutos
        self.last_discovery = 0
        
        # Configuración de red
        self.ping_timeout = 5
        self.ping_interval = 60
        self.sync_interval = 10
        
    def add_bootstrap_node(self, address: tuple):
        """Añade nodo bootstrap"""
        self.bootstrap_nodes.append(address)
    
    def discover_peers(self) -> List[tuple]:
        """Descubre nuevos peers usando DHT"""
        current_time = time.time()
        
        if current_time - self.last_discovery < self.discovery_interval:
            return []
        
        discovered_peers = []
        
        # Usar nodos bootstrap para descubrimiento inicial
        for bootstrap_addr in self.bootstrap_nodes:
            try:
                # En implementación real, esto enviaría mensajes FIND_NODE
                # Por ahora simulamos descubrimiento
                fake_peers = self._simulate_peer_discovery(bootstrap_addr)
                discovered_peers.extend(fake_peers)
            except Exception as e:
                print(f"Error discovering peers from {bootstrap_addr}: {e}")
        
        # Usar DHT para descubrimiento
        if len(self.dht_node.routing_table) > 0:
            # Buscar peers cercanos a nuestro ID
            closest_peers = self.dht_node.get_closest_peers(self.node_id, 20)
            discovered_peers.extend(closest_peers)
        
        self.last_discovery = current_time
        return discovered_peers
    
    def _simulate_peer_discovery(self, bootstrap_addr: tuple) -> List[tuple]:
        """Simula descubrimiento de peers (en implementación real sería real)"""
        # Generar algunos peers falsos para demostración
        fake_peers = []
        for i in range(5):
            fake_id = f"{random.randint(0, 2**160-1):040x}"
            fake_addr = (f"192.168.1.{100 + i}", 30303 + i)
            fake_peers.append((fake_id, fake_addr))
        return fake_peers
    
    def connect_to_peer(self, peer_id: str, peer_address: tuple) -> bool:
        """Conecta a un peer específico"""
        # Verificar protección contra eclipse
        if self.eclipse_protection.is_suspicious_peer(peer_id, peer_address):
            print(f"Rejecting suspicious peer: {peer_id}")
            return False
        
        # Verificar límite de conexiones
        if len(self.connected_peers) >= self.max_peers:
            print("Maximum peer connections reached")
            return False
        
        try:
            # En implementación real, esto establecería conexión TCP/UDP
            # Por ahora simulamos conexión exitosa
            connection_info = {
                'id': peer_id,
                'address': peer_address,
                'connected_at': time.time(),
                'last_ping': time.time(),
                'reputation': 100,
                'sync_status': 'syncing'
            }
            
            self.connected_peers[peer_id] = connection_info
            self.dht_node.add_peer(peer_id, peer_address)
            self.eclipse_protection.record_connection(peer_id, peer_address)
            
            print(f"Connected to peer {peer_id} at {peer_address}")
            return True
            
        except Exception as e:
            print(f"Failed to connect to peer {peer_id}: {e}")
            return False
    
    def disconnect_peer(self, peer_id: str):
        """Desconecta de un peer"""
        if peer_id in self.connected_peers:
            del self.connected_peers[peer_id]
            print(f"Disconnected from peer {peer_id}")
    
    def ping_peers(self):
        """Envía ping a todos los peers conectados"""
        current_time = time.time()
        peers_to_remove = []
        
        for peer_id, peer_info in self.connected_peers.items():
            if current_time - peer_info['last_ping'] > self.ping_interval:
                try:
                    # En implementación real, esto enviaría PING
                    # Por ahora simulamos ping exitoso
                    success = self._simulate_ping(peer_id)
                    
                    if success:
                        peer_info['last_ping'] = current_time
                        self.eclipse_protection.update_peer_reputation(peer_id, True)
                    else:
                        peers_to_remove.append(peer_id)
                        self.eclipse_protection.update_peer_reputation(peer_id, False)
                        
                except Exception as e:
                    print(f"Ping failed for peer {peer_id}: {e}")
                    peers_to_remove.append(peer_id)
        
        # Remover peers que no respondieron
        for peer_id in peers_to_remove:
            self.disconnect_peer(peer_id)
    
    def _simulate_ping(self, peer_id: str) -> bool:
        """Simula ping a peer (en implementación real sería real)"""
        # 90% de éxito para simulación
        return random.random() < 0.9
    
    def sync_with_peers(self, blockchain_height: int) -> List[dict]:
        """Sincroniza con peers para obtener bloques"""
        current_time = time.time()
        new_blocks = []
        
        for peer_id, peer_info in self.connected_peers.items():
            if current_time - peer_info.get('last_sync', 0) > self.sync_interval:
                try:
                    # En implementación real, esto solicitaría bloques
                    # Por ahora simulamos sincronización
                    peer_blocks = self._simulate_block_sync(peer_id, blockchain_height)
                    new_blocks.extend(peer_blocks)
                    peer_info['last_sync'] = current_time
                    
                except Exception as e:
                    print(f"Sync failed with peer {peer_id}: {e}")
        
        return new_blocks
    
    def _simulate_block_sync(self, peer_id: str, current_height: int) -> List[dict]:
        """Simula sincronización de bloques (en implementación real sería real)"""
        # Simular algunos bloques nuevos
        new_blocks = []
        for i in range(random.randint(0, 3)):
            block = {
                'height': current_height + i + 1,
                'hash': f"block_{current_height + i + 1}",
                'timestamp': time.time(),
                'peer_id': peer_id
            }
            new_blocks.append(block)
        return new_blocks
    
    def broadcast_message(self, message: dict, exclude_peers: List[str] = None):
        """Transmite mensaje a todos los peers conectados"""
        if exclude_peers is None:
            exclude_peers = []
        
        for peer_id, peer_info in self.connected_peers.items():
            if peer_id not in exclude_peers:
                try:
                    # En implementación real, esto enviaría el mensaje
                    self._simulate_message_send(peer_id, message)
                except Exception as e:
                    print(f"Failed to send message to peer {peer_id}: {e}")
    
    def _simulate_message_send(self, peer_id: str, message: dict):
        """Simula envío de mensaje (en implementación real sería real)"""
        print(f"Sending message to peer {peer_id}: {message.get('type', 'unknown')}")
    
    def get_network_info(self) -> dict:
        """Obtiene información de la red"""
        return {
            'node_id': self.node_id,
            'listen_address': self.listen_address,
            'connected_peers': len(self.connected_peers),
            'max_peers': self.max_peers,
            'bootstrap_nodes': len(self.bootstrap_nodes),
            'dht_peers': len(self.dht_node.routing_table),
            'suspicious_peers': len(self.eclipse_protection.suspicious_peers),
            'last_discovery': self.last_discovery
        }
    
    def get_peer_list(self) -> List[dict]:
        """Obtiene lista de peers conectados"""
        peer_list = []
        for peer_id, peer_info in self.connected_peers.items():
            peer_list.append({
                'id': peer_id,
                'address': peer_info['address'],
                'connected_at': peer_info['connected_at'],
                'reputation': peer_info['reputation'],
                'sync_status': peer_info['sync_status']
            })
        return peer_list
