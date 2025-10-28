"""
Protección contra ataques de eclipse
"""

import time
from typing import Dict, Set, List
from collections import defaultdict

class EclipseAttackProtection:
    """Protección contra ataques de eclipse"""
    
    def __init__(self):
        self.suspicious_peers = set()
        self.connection_history = defaultdict(list)  # ip -> [timestamps]
        self.reputation_scores = {}  # peer_id -> score
        self.max_connections_per_ip = 5
        self.connection_window = 300  # 5 minutos
        self.min_reputation = 50
        
    def is_suspicious_peer(self, peer_id: str, address: tuple) -> bool:
        """Verifica si un peer es sospechoso"""
        ip, port = address
        
        # Verificar si está en lista de sospechosos
        if peer_id in self.suspicious_peers:
            return True
        
        # Verificar límite de conexiones por IP
        current_time = time.time()
        recent_connections = [
            ts for ts in self.connection_history[ip] 
            if current_time - ts < self.connection_window
        ]
        
        if len(recent_connections) >= self.max_connections_per_ip:
            return True
        
        # Verificar reputación
        if peer_id in self.reputation_scores:
            if self.reputation_scores[peer_id] < self.min_reputation:
                return True
        
        return False
    
    def record_connection(self, peer_id: str, address: tuple):
        """Registra nueva conexión"""
        ip, port = address
        current_time = time.time()
        
        # Añadir timestamp a historial
        self.connection_history[ip].append(current_time)
        
        # Limpiar timestamps antiguos
        self.connection_history[ip] = [
            ts for ts in self.connection_history[ip]
            if current_time - ts < self.connection_window
        ]
        
        # Inicializar reputación si es nuevo peer
        if peer_id not in self.reputation_scores:
            self.reputation_scores[peer_id] = 100
    
    def update_peer_reputation(self, peer_id: str, success: bool):
        """Actualiza reputación de un peer"""
        if peer_id not in self.reputation_scores:
            self.reputation_scores[peer_id] = 100
        
        if success:
            # Aumentar reputación
            self.reputation_scores[peer_id] = min(100, 
                self.reputation_scores[peer_id] + 1)
        else:
            # Disminuir reputación
            self.reputation_scores[peer_id] = max(0, 
                self.reputation_scores[peer_id] - 5)
            
            # Marcar como sospechoso si reputación muy baja
            if self.reputation_scores[peer_id] < 20:
                self.suspicious_peers.add(peer_id)
    
    def flag_suspicious_peer(self, peer_id: str, reason: str):
        """Marca peer como sospechoso"""
        self.suspicious_peers.add(peer_id)
        if peer_id in self.reputation_scores:
            self.reputation_scores[peer_id] = 0
    
    def get_protection_stats(self) -> dict:
        """Obtiene estadísticas de protección"""
        return {
            'suspicious_peers': len(self.suspicious_peers),
            'tracked_ips': len(self.connection_history),
            'total_peers': len(self.reputation_scores),
            'avg_reputation': sum(self.reputation_scores.values()) / len(self.reputation_scores) 
                if self.reputation_scores else 0
        }
    
    def cleanup_old_data(self, max_age: int = 3600):
        """Limpia datos antiguos"""
        current_time = time.time()
        
        # Limpiar historial de conexiones
        for ip in list(self.connection_history.keys()):
            self.connection_history[ip] = [
                ts for ts in self.connection_history[ip]
                if current_time - ts < max_age
            ]
            
            # Remover IPs sin conexiones recientes
            if not self.connection_history[ip]:
                del self.connection_history[ip]
