# API endpoints package
from app.api.radius_endpoints import router as radius_router
from app.api.radius_hotspot import router as radius_hotspot_router

__all__ = ['radius_router', 'radius_hotspot_router']
