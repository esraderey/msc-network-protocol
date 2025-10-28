"""
Sistema de Oracle para precios y datos externos
"""

import asyncio
import aiohttp
import time
from typing import Dict, Any, Optional
from decimal import Decimal

class OracleSystem:
    """Sistema de Oracle descentralizado para precios"""

    def __init__(self):
        self.price_feeds = {}  # asset -> price data
        self.oracle_nodes = []  # Lista de nodos oracle
        self.update_interval = 60  # segundos
        self.price_threshold = Decimal('0.05')  # 5% cambio mínimo

    async def add_price_feed(self, asset: str, source_url: str):
        """Añade feed de precio para un activo"""
        self.price_feeds[asset] = {
            'url': source_url,
            'price': Decimal('0'),
            'last_update': 0,
            'confidence': 1.0
        }

    async def update_prices(self):
        """Actualiza precios desde fuentes externas"""
        tasks = []
        for asset, feed in self.price_feeds.items():
            task = asyncio.create_task(self._fetch_price(asset, feed))
            tasks.append(task)

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _fetch_price(self, asset: str, feed: Dict[str, Any]):
        """Obtiene precio de una fuente externa"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(feed['url'], timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        price = self._extract_price(data)
                        
                        if price and self._is_price_valid(price, feed['price']):
                            feed['price'] = price
                            feed['last_update'] = int(time.time())
                            feed['confidence'] = 1.0
        except Exception as e:
            # Reducir confianza en caso de error
            feed['confidence'] *= 0.9

    def _extract_price(self, data: Dict[str, Any]) -> Optional[Decimal]:
        """Extrae precio de la respuesta JSON"""
        # Implementación simplificada - en producción sería más robusta
        if 'price' in data:
            return Decimal(str(data['price']))
        elif 'result' in data and 'price' in data['result']:
            return Decimal(str(data['result']['price']))
        return None

    def _is_price_valid(self, new_price: Decimal, old_price: Decimal) -> bool:
        """Verifica si el nuevo precio es válido"""
        if old_price == 0:
            return True
        
        change = abs(new_price - old_price) / old_price
        return change <= self.price_threshold

    def get_price(self, asset: str) -> Optional[Decimal]:
        """Obtiene precio actual de un activo"""
        if asset in self.price_feeds:
            return self.price_feeds[asset]['price']
        return None

    def get_price_with_confidence(self, asset: str) -> Optional[tuple]:
        """Obtiene precio con nivel de confianza"""
        if asset in self.price_feeds:
            feed = self.price_feeds[asset]
            return feed['price'], feed['confidence']
        return None

    async def start_price_updates(self):
        """Inicia actualizaciones periódicas de precios"""
        while True:
            await self.update_prices()
            await asyncio.sleep(self.update_interval)
