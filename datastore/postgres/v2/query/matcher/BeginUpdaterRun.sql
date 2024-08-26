WITH
  u AS (
    SELECT
      id
    FROM
      updater_v1.updater
    WHERE
      name = $2
  )
INSERT INTO
  updater_v1.run (ref, updater, fingerprint)
VALUES
  ($1, u.id, $3::JSONB)
RETURNING
  id;
