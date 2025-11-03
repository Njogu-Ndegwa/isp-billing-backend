from typing import Any, Optional, Dict, Callable
from datetime import datetime, timedelta
import asyncio
import logging

logger = logging.getLogger(__name__)

class CacheEntry:
    def __init__(self, value: Any, ttl_seconds: int):
        self.value = value
        self.expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
    
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

class InMemoryCache:
    def __init__(self):
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = asyncio.Lock()
    
    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            
            if entry.is_expired():
                del self._cache[key]
                return None
            
            return entry.value
    
    async def set(self, key: str, value: Any, ttl_seconds: int = 300):
        async with self._lock:
            self._cache[key] = CacheEntry(value, ttl_seconds)
    
    async def delete(self, key: str):
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
    
    async def clear_pattern(self, pattern: str):
        """Delete all keys that start with pattern"""
        async with self._lock:
            keys_to_delete = [k for k in self._cache.keys() if k.startswith(pattern)]
            for key in keys_to_delete:
                del self._cache[key]
    
    async def clear(self):
        async with self._lock:
            self._cache.clear()
    
    async def get_or_set(
        self, 
        key: str, 
        factory: Callable, 
        ttl_seconds: int = 300
    ) -> Any:
        """Get from cache or compute and cache the value"""
        cached = await self.get(key)
        if cached is not None:
            return cached
        
        value = await factory()
        await self.set(key, value, ttl_seconds)
        return value

# Global cache instance
cache = InMemoryCache()

