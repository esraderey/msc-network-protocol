"""
Gestor de red P2P con DHT y protección contra eclipse
"""

import time
import json
import socket
import asyncio
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
        self.server = None
        self._client_tasks = set()
        self.blockchain = None

    async def start(self):
        """Inicia el listener TCP JSON-lines del nodo."""
        if self.server is not None:
            return
        host, port = self._validate_listen_address(self.listen_address)
        self.server = await asyncio.start_server(
            self._handle_client, host, port, limit=1_048_576
        )
        socket_address = self.server.sockets[0].getsockname()
        self.listen_address = (socket_address[0], socket_address[1])

    async def stop(self):
        """Cierra el listener y las conexiones entrantes activas."""
        server = self.server
        self.server = None
        if server is not None:
            try:
                server.close()
                await server.wait_closed()
            except (AttributeError, RuntimeError):
                # Windows Proactor no puede cerrar un Server asociado a otro
                # event loop; cerrar explícitamente sus sockets libera el puerto.
                for listening_socket in server.sockets or ():
                    listening_socket.close()
        tasks = list(self._client_tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._client_tasks.clear()

    @staticmethod
    def _validate_listen_address(address: tuple) -> tuple:
        if not isinstance(address, (tuple, list)) or len(address) != 2:
            raise ValueError("listen address must be (host, port)")
        host, port = address
        if not isinstance(host, str) or not host.strip():
            raise ValueError("listen host must be a non-empty string")
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError("listen port must be between 0 and 65535")
        return host.strip(), port

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter):
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        peer_address = writer.get_extra_info('peername')
        try:
            while True:
                try:
                    line = await reader.readuntil(b'\n')
                except asyncio.IncompleteReadError:
                    break
                if len(line) > 1_048_576:
                    await self._write_response(writer, {'type': 'error', 'error': 'message too large'})
                    break
                try:
                    message = json.loads(line.decode('utf-8'))
                    response = await self._handle_message(message, peer_address)
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                    response = {'type': 'error', 'error': str(exc)}
                if response is not None:
                    await self._write_response(writer, response)
        finally:
            writer.close()
            await writer.wait_closed()
            if task is not None:
                self._client_tasks.discard(task)

    async def _write_response(self, writer: asyncio.StreamWriter, response: dict):
        writer.write((json.dumps(response, sort_keys=True) + '\n').encode('utf-8'))
        await writer.drain()

    async def _handle_message(self, message: dict, peer_address) -> dict:
        if not isinstance(message, dict) or not isinstance(message.get('type'), str):
            raise ValueError("message must contain a type")
        message_type = message['type']
        if message_type == 'hello':
            peer_id = message.get('node_id')
            if not isinstance(peer_id, str) or not peer_id or peer_id == self.node_id:
                raise ValueError("invalid peer node_id")
            advertised = message.get('listen_address', peer_address)
            try:
                address = self._validate_address(tuple(advertised))
            except (TypeError, ValueError):
                address = self._validate_address(tuple(peer_address[:2]))
            if self.eclipse_protection.is_suspicious_peer(peer_id, address):
                raise ValueError("peer rejected by eclipse protection")
            if peer_id not in self.connected_peers and len(self.connected_peers) >= self.max_peers:
                raise ValueError("maximum peer connections reached")
            self._register_peer(peer_id, address)
            return {'type': 'hello_ack', 'node_id': self.node_id}
        if message_type == 'ping':
            return {'type': 'pong', 'node_id': self.node_id}
        if message_type == 'get_blocks':
            return {'type': 'blocks', 'blocks': self._serialize_blocks(message.get('from_height', 0))}
        if message_type == 'transaction':
            accepted = await self._accept_transaction(message.get('transaction'))
            return {'type': 'transaction_ack', 'accepted': accepted}
        raise ValueError(f"unsupported message type: {message_type}")

    def _register_peer(self, peer_id: str, address: tuple):
        now = time.time()
        existing = self.connected_peers.get(peer_id, {})
        self.connected_peers[peer_id] = {
            'id': peer_id,
            'address': address,
            'connected_at': existing.get('connected_at', now),
            'last_ping': now,
            'reputation': existing.get('reputation', 100),
            'sync_status': existing.get('sync_status', 'connected'),
        }
        self.dht_node.add_peer(peer_id, address)
        self.eclipse_protection.record_connection(peer_id, address)

    def _serialize_blocks(self, from_height: Any) -> List[dict]:
        if not isinstance(from_height, int) or from_height < 0:
            raise ValueError("from_height must be a non-negative integer")
        if self.blockchain is None:
            return []
        blocks = []
        for block in self.blockchain.chain[from_height:from_height + 100]:
            blocks.append({
                'height': block.header.number,
                'hash': block.hash,
                'parent_hash': block.header.parent_hash,
                'timestamp': block.header.timestamp,
                'transactions': [tx.calculate_hash() for tx in block.transactions],
            })
        return blocks

    async def _accept_transaction(self, payload: Any) -> bool:
        if self.blockchain is None or not isinstance(payload, dict):
            return False
        try:
            from ..core.transaction import Transaction
            tx = Transaction(
                nonce=int(payload['nonce']),
                gas_price=int(payload['gas_price']),
                gas_limit=int(payload['gas_limit']),
                to=payload.get('to'),
                value=int(payload['value']),
                data=bytes.fromhex(payload.get('data', '')),
                v=payload.get('v'),
                r=payload.get('r'),
                s=payload.get('s'),
                chain_id=int(payload['chain_id']),
            )
            return await self.blockchain.add_transaction(tx, broadcast=False)
        except (KeyError, TypeError, ValueError):
            return False
        
    def add_bootstrap_node(self, address: tuple):
        """Añade nodo bootstrap"""
        self.bootstrap_nodes.append(address)
    
    def discover_peers(self) -> List[tuple]:
        """Devuelve peers conocidos por la DHT.

        El descubrimiento no inventa nodos: los bootstrap requieren un
        protocolo FIND_NODE real antes de poder aportar peers confiables.
        """
        current_time = time.time()
        
        if current_time - self.last_discovery < self.discovery_interval:
            return []
        
        discovered_peers = self.dht_node.get_closest_peers(self.node_id, 20)
        
        self.last_discovery = current_time
        return discovered_peers

    @staticmethod
    def _validate_address(address: tuple) -> tuple:
        if not isinstance(address, (tuple, list)) or len(address) != 2:
            raise ValueError("peer address must be (host, port)")
        host, port = address
        if not isinstance(host, str) or not host.strip():
            raise ValueError("peer host must be a non-empty string")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("peer port must be between 1 and 65535")
        return host.strip(), port

    def _exchange(self, address: tuple, message: dict, expect_response: bool = False):
        address = self._validate_address(address)
        payload = (json.dumps(message, sort_keys=True) + "\n").encode("utf-8")
        with socket.create_connection(address, timeout=self.ping_timeout) as connection:
            connection.sendall(payload)
            if not expect_response:
                return None
            response = b""
            while b"\n" not in response and len(response) <= 1_048_576:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response += chunk
            if b"\n" not in response:
                raise ConnectionError("peer returned no complete response")
            return json.loads(response.split(b"\n", 1)[0].decode("utf-8"))
    
    def connect_to_peer(self, peer_id: str, peer_address: tuple) -> bool:
        """Conecta a un peer específico"""
        if not isinstance(peer_id, str) or not peer_id or peer_id == self.node_id:
            return False
        peer_address = self._validate_address(peer_address)
        # Verificar protección contra eclipse
        if self.eclipse_protection.is_suspicious_peer(peer_id, peer_address):
            print(f"Rejecting suspicious peer: {peer_id}")
            return False
        
        # Verificar límite de conexiones
        if len(self.connected_peers) >= self.max_peers:
            print("Maximum peer connections reached")
            return False
        
        try:
            response = self._exchange(peer_address, {
                'type': 'hello',
                'node_id': self.node_id,
                'listen_address': self.listen_address,
            }, expect_response=True)
            if not isinstance(response, dict) or response.get('type') != 'hello_ack':
                raise ConnectionError("peer did not acknowledge hello")
            self._register_peer(peer_id, peer_address)
            
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
                    self._exchange(peer_info['address'], {
                        'type': 'ping',
                        'node_id': self.node_id,
                    })
                    peer_info['last_ping'] = current_time
                    self.eclipse_protection.update_peer_reputation(peer_id, True)
                        
                except Exception as e:
                    print(f"Ping failed for peer {peer_id}: {e}")
                    peers_to_remove.append(peer_id)
                    self.eclipse_protection.update_peer_reputation(peer_id, False)
        
        # Remover peers que no respondieron
        for peer_id in peers_to_remove:
            self.disconnect_peer(peer_id)
    
    def sync_with_peers(self, blockchain_height: int) -> List[dict]:
        """Sincroniza con peers para obtener bloques"""
        current_time = time.time()
        new_blocks = []
        
        for peer_id, peer_info in self.connected_peers.items():
            if current_time - peer_info.get('last_sync', 0) > self.sync_interval:
                try:
                    response = self._exchange(peer_info['address'], {
                        'type': 'get_blocks',
                        'from_height': blockchain_height + 1,
                    }, expect_response=True)
                    peer_blocks = response.get('blocks', []) if isinstance(response, dict) else response
                    if not isinstance(peer_blocks, list) or not all(isinstance(block, dict) for block in peer_blocks):
                        raise ValueError("peer returned an invalid block list")
                    new_blocks.extend(peer_blocks)
                    peer_info['last_sync'] = current_time
                    
                except Exception as e:
                    print(f"Sync failed with peer {peer_id}: {e}")
        
        return new_blocks
    
    def broadcast_message(self, message: dict, exclude_peers: List[str] = None):
        """Transmite mensaje a todos los peers conectados"""
        if exclude_peers is None:
            exclude_peers = []
        
        for peer_id, peer_info in self.connected_peers.items():
            if peer_id not in exclude_peers:
                try:
                    self._exchange(peer_info['address'], message)
                except Exception as e:
                    print(f"Failed to send message to peer {peer_id}: {e}")
    
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
