#!/bin/bash
set -e

# Usage: ./backup.sh
# Requires: PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="backup_$DATE.sql"

pg_dump -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -F c -b -v -f "$BACKUP_FILE"
echo "Backup completed: $BACKUP_FILE" 