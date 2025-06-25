INSERT
OR REPLACE INTO meta (key, value)
VALUES
  (?, ?) ON CONFLICT (key) DO
UPDATE
SET
  value = excluded.value
