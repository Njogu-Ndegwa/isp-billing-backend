"""
Database initialization script for PostgreSQL.
Run this after starting the containers to create all tables.
"""
import asyncio
from app.db.database import async_engine, Base
from app.db.models import *  # Import all models

async def init_db():
    async with async_engine.begin() as conn:
        # Drop all tables (use with caution)
        # await conn.run_sync(Base.metadata.drop_all)
        
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)
    
    print("Database tables created successfully!")

if __name__ == "__main__":
    asyncio.run(init_db())

