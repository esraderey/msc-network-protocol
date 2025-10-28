"""
Nodo DHT para descubrimiento de peers
"""

import hashlib
import time
from typing import Dict, List, Tuple, Optional

class DHTNode:
    """Nodo DHT para descubrimiento de peers"""
    
    def __init__(self, node_id: str, listen_address: tuple):
        self.node_id = node_id
        self.listen_address = listen_address
        self.routing_table = {}  # peer_id -> (address, last_seen)
        self.buckets = {}  # bucket_id -> [peer_ids]
        self.max_bucket_size = 20
        self.bucket_count = 160  # Para IDs de 160 bits
        
    def add_peer(self, peer_id: str, address: tuple):
        """Añade peer a la tabla de enrutamiento"""
        bucket_id = self._get_bucket_id(peer_id)
        
        if bucket_id not in self.buckets:
            self.buckets[bucket_id] = []
        
        # Verificar si el bucket está lleno
        if len(self.buckets[bucket_id]) >= self.max_bucket_size:
            # Reemplazar peer menos reciente
            oldest_peer = min(self.buckets[bucket_id], 
                            key=lambda p: self.routing_table[p][1])
            del self.routing_table[oldest_peer]
            self.buckets[bucket_id].remove(oldest_peer)
        
        # Añadir nuevo peer
        self.routing_table[peer_id] = (address, time.time())
        if peer_id not in self.buckets[bucket_id]:
            self.buckets[bucket_id].append(peer_id)
    
    def remove_peer(self, peer_id: str):
        """Remueve peer de la tabla de enrutamiento"""
        if peer_id in self.routing_table:
            bucket_id = self._get_bucket_id(peer_id)
            del self.routing_table[peer_id]
            if bucket_id in self.buckets and peer_id in self.buckets[bucket_id]:
                self.buckets[bucket_id].remove(peer_id)
    
    def get_peer(self, peer_id: str) -> Optional[tuple]:
        """Obtiene información de un peer"""
        if peer_id in self.routing_table:
            address, last_seen = self.routing_table[peer_id]
            return address
        return None
    
    def get_closest_peers(self, target_id: str, count: int) -> List[tuple]:
        """Obtiene los peers más cercanos a un ID objetivo"""
        # Calcular distancia XOR entre IDs
        distances = []
        for peer_id, (address, last_seen) in self.routing_table.items():
            distance = self._xor_distance(target_id, peer_id)
            distances.append((distance, peer_id, address))
        
        # Ordenar por distancia y tomar los más cercanos
        distances.sort(key=lambda x: x[0])
        closest = distances[:count]
        
        return [(peer_id, address) for _, peer_id, address in closest]
    
    def _get_bucket_id(self, peer_id: str) -> int:
        """Obtiene ID del bucket para un peer"""
        # Calcular distancia XOR
        distance = self._xor_distance(self.node_id, peer_id)
        
        # Encontrar el bit más significativo diferente
        if distance == 0:
            return 0
        
        # Contar ceros a la izquierda
        bucket_id = 0
        while distance > 0:
            distance >>= 1
            bucket_id += 1
        
        return min(bucket_id, self.bucket_count - 1)
    
    def _xor_distance(self, id1: str, id2: str) -> int:
        """Calcula distancia XOR entre dos IDs"""
        # Convertir IDs hex a enteros
        int1 = int(id1, 16)
        int2 = int(id2, 16)
        
        # Calcular XOR
        return int1 ^ int2
    
    def cleanup_stale_peers(self, max_age: int = 3600):
        """Limpia peers que no se han visto recientemente"""
        current_time = time.time()
        stale_peers = []
        
        for peer_id, (address, last_seen) in self.routing_table.items():
            if current_time - last_seen > max_age:
                stale_peers.append(peer_id)
        
        for peer_id in stale_peers:
            self.remove_peer(peer_id)
    
    def get_routing_table_info(self) -> dict:
        """Obtiene información de la tabla de enrutamiento"""
        return {
            'total_peers': len(self.routing_table),
            'buckets_used': len(self.buckets),
            'max_bucket_size': self.max_bucket_size,
            'bucket_count': self.bucket_count
        }
