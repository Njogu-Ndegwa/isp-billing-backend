# FreeRADIUS with PostgreSQL support
# Based on official image (Debian-based), adds PostgreSQL client library needed at runtime
FROM freeradius/freeradius-server:3.2.3

# Install PostgreSQL client library (required by rlm_sql_postgresql)
USER root
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 && \
    rm -rf /var/lib/apt/lists/*
USER freerad

# Default command: run in foreground with stdout logging
CMD ["radiusd", "-f", "-l", "stdout"]
