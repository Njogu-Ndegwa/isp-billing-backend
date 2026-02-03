"""
Migration script to add location fields to customers and create customer_ratings table.
Run this once to update your database schema.

Usage: python migrate_add_location_ratings.py
"""
import asyncio
from sqlalchemy import text
from app.db.database import async_engine

MIGRATION_SQL = """
-- Add location columns to customers table
ALTER TABLE customers ADD COLUMN IF NOT EXISTS latitude FLOAT;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS longitude FLOAT;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS location_captured_at TIMESTAMP;

-- Create the customer_ratings table (customer_id is nullable to allow non-customers)
CREATE TABLE IF NOT EXISTS customer_ratings (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    phone VARCHAR NOT NULL,
    rating INTEGER NOT NULL,
    comment VARCHAR(500),
    service_quality INTEGER,
    support_rating INTEGER,
    value_for_money INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    latitude FLOAT,
    longitude FLOAT
);

-- Make customer_id nullable for existing tables (allows non-customers to submit ratings)
ALTER TABLE customer_ratings ALTER COLUMN customer_id DROP NOT NULL;

-- Add indexes for better query performance
CREATE INDEX IF NOT EXISTS ix_customer_ratings_phone ON customer_ratings(phone);
CREATE INDEX IF NOT EXISTS ix_customer_ratings_created_at ON customer_ratings(created_at);
"""

async def run_migration():
    print("Starting migration...")
    
    async with async_engine.begin() as conn:
        # Split and execute each statement
        statements = [s.strip() for s in MIGRATION_SQL.split(';') if s.strip()]
        
        for i, statement in enumerate(statements, 1):
            try:
                await conn.execute(text(statement))
                print(f"✓ Statement {i} executed successfully")
            except Exception as e:
                # Ignore "already exists" errors
                if "already exists" in str(e).lower() or "duplicate" in str(e).lower():
                    print(f"⚠ Statement {i} skipped (already exists)")
                else:
                    print(f"✗ Statement {i} failed: {e}")
    
    print("\n✅ Migration completed!")
    print("You can now use the location and rating features.")

if __name__ == "__main__":
    asyncio.run(run_migration())
