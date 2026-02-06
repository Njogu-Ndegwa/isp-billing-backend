# FreeRADIUS with PostgreSQL support
# Based on official image, adds PostgreSQL client libraries needed at runtime
FROM freeradius/freeradius-server:3.2.3

# Install PostgreSQL client library (required for rlm_sql_postgresql)
USER root
RUN apk add --no-cache postgresql-libs postgresql-dev
USER freerad

# Default command: run in foreground with stdout logging
CMD ["radiusd", "-f", "-l", "stdout"]
