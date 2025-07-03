INSERT OR REPLACE INTO
  meta (key, value)
VALUES
  (:key, :value)
ON CONFLICT (key) DO UPDATE
SET
  value = excluded.value
