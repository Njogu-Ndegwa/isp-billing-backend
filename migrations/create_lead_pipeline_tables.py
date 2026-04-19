"""
Migration: Create lead pipeline tables

Creates the tables required for the lead / sales pipeline feature:
  - lead_sources        (managed list of lead sources)
  - leads               (pipeline records with stage, contact info, etc.)
  - lead_activities     (timeline entries: notes, calls, stage changes, ...)
  - lead_follow_ups     (scheduled follow-up reminders)

Also creates the supporting PostgreSQL enum types:
  - leadstage           (new_lead, contacted, talking, installation_help,
                         signed_up, paying, churned, lost)
  - leadactivitytype    (note, call, dm, email, meeting, stage_change,
                         followup_completed, other)

Safe to run multiple times — skips objects that already exist.

Usage:
    python migrations/create_lead_pipeline_tables.py

Rollback (drops tables and enum types):
    python migrations/create_lead_pipeline_tables.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def _table_exists(conn, table_name: str) -> bool:
    result = await conn.execute(
        text(
            """
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = :t
            """
        ),
        {"t": table_name},
    )
    return result.fetchone() is not None


async def migrate():
    """Create lead pipeline tables and enums."""
    async with engine.begin() as conn:
        # --- Enums --------------------------------------------------------
        await conn.execute(
            text(
                """
                DO $$ BEGIN
                    CREATE TYPE leadstage AS ENUM (
                        'new_lead',
                        'contacted',
                        'talking',
                        'installation_help',
                        'signed_up',
                        'paying',
                        'churned',
                        'lost'
                    );
                EXCEPTION WHEN duplicate_object THEN NULL;
                END $$;
                """
            )
        )

        await conn.execute(
            text(
                """
                DO $$ BEGIN
                    CREATE TYPE leadactivitytype AS ENUM (
                        'note',
                        'call',
                        'dm',
                        'email',
                        'meeting',
                        'stage_change',
                        'followup_completed',
                        'other'
                    );
                EXCEPTION WHEN duplicate_object THEN NULL;
                END $$;
                """
            )
        )

        # --- lead_sources -------------------------------------------------
        if not await _table_exists(conn, "lead_sources"):
            await conn.execute(
                text(
                    """
                    CREATE TABLE lead_sources (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(100) NOT NULL UNIQUE,
                        description VARCHAR(255),
                        is_active BOOLEAN NOT NULL DEFAULT TRUE,
                        user_id INTEGER NOT NULL REFERENCES users(id),
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                    """
                )
            )
            print("  Created table: lead_sources")
        else:
            print("  Table lead_sources already exists, skipping")

        # --- leads --------------------------------------------------------
        if not await _table_exists(conn, "leads"):
            await conn.execute(
                text(
                    """
                    CREATE TABLE leads (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL REFERENCES users(id),
                        name VARCHAR(255) NOT NULL,
                        phone VARCHAR(20),
                        email VARCHAR(255),
                        social_platform VARCHAR(50),
                        social_handle VARCHAR(100),
                        source_id INTEGER REFERENCES lead_sources(id),
                        source_detail VARCHAR(500),
                        stage leadstage NOT NULL DEFAULT 'new_lead',
                        stage_changed_at TIMESTAMP DEFAULT NOW(),
                        next_followup_at TIMESTAMP,
                        notes VARCHAR(2000),
                        converted_user_id INTEGER REFERENCES users(id),
                        lost_reason VARCHAR(500),
                        created_at TIMESTAMP DEFAULT NOW(),
                        updated_at TIMESTAMP DEFAULT NOW()
                    )
                    """
                )
            )
            await conn.execute(text("CREATE INDEX idx_leads_user_id ON leads(user_id)"))
            await conn.execute(text("CREATE INDEX idx_leads_source_id ON leads(source_id)"))
            await conn.execute(text("CREATE INDEX idx_leads_next_followup_at ON leads(next_followup_at)"))
            await conn.execute(text("CREATE INDEX idx_leads_created_at ON leads(created_at)"))
            print("  Created table: leads")
        else:
            print("  Table leads already exists, skipping")

        # --- lead_activities ---------------------------------------------
        if not await _table_exists(conn, "lead_activities"):
            await conn.execute(
                text(
                    """
                    CREATE TABLE lead_activities (
                        id SERIAL PRIMARY KEY,
                        lead_id INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
                        activity_type leadactivitytype NOT NULL,
                        description VARCHAR(2000),
                        old_stage VARCHAR(50),
                        new_stage VARCHAR(50),
                        created_by INTEGER NOT NULL REFERENCES users(id),
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                    """
                )
            )
            await conn.execute(text("CREATE INDEX idx_lead_activities_lead_id ON lead_activities(lead_id)"))
            await conn.execute(text("CREATE INDEX idx_lead_activities_created_at ON lead_activities(created_at)"))
            print("  Created table: lead_activities")
        else:
            print("  Table lead_activities already exists, skipping")

        # --- lead_follow_ups ---------------------------------------------
        if not await _table_exists(conn, "lead_follow_ups"):
            await conn.execute(
                text(
                    """
                    CREATE TABLE lead_follow_ups (
                        id SERIAL PRIMARY KEY,
                        lead_id INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
                        title VARCHAR(255) NOT NULL,
                        due_at TIMESTAMP NOT NULL,
                        is_completed BOOLEAN NOT NULL DEFAULT FALSE,
                        completed_at TIMESTAMP,
                        created_by INTEGER NOT NULL REFERENCES users(id),
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                    """
                )
            )
            await conn.execute(text("CREATE INDEX idx_lead_follow_ups_lead_id ON lead_follow_ups(lead_id)"))
            await conn.execute(text("CREATE INDEX idx_lead_follow_ups_due_at ON lead_follow_ups(due_at)"))
            print("  Created table: lead_follow_ups")
        else:
            print("  Table lead_follow_ups already exists, skipping")

        print("Lead pipeline migration completed successfully!")


async def rollback():
    """Drop lead pipeline tables and enum types."""
    async with engine.begin() as conn:
        for table in (
            "lead_follow_ups",
            "lead_activities",
            "leads",
            "lead_sources",
        ):
            await conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
            print(f"  Dropped table: {table}")

        for enum_name in ("leadactivitytype", "leadstage"):
            await conn.execute(text(f"DROP TYPE IF EXISTS {enum_name}"))
            print(f"  Dropped type:  {enum_name}")

        print("Rollback completed successfully!")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Lead pipeline tables migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())
