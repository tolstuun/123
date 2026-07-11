# Backup and Restore

Create a timestamped compressed custom-format dump with `cd /home/deploy/vmray-analytics && ./ops/backup.sh`. Files are mode-restricted under the ignored `backups/` directory.

Restore only during an approved maintenance window: stop web/collector, decompress the selected dump, and pipe it to `pg_restore --clean --if-exists` in the database container. Restore is intentionally manual because it replaces production state.
