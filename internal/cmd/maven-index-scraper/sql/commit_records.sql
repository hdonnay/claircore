INSERT INTO
  repository
SELECT
  *
FROM
  to_add
WHERE
  true ON CONFLICT (sha1) DO NOTHING ON CONFLICT (sha256) DO NOTHING ON CONFLICT (groupId, artifactId, version) DO
UPDATE
SET
  sha1 = COALESCE(excluded.sha1, sha1),
  sha256 = COALESCE(excluded.sha256, sha256);

DELETE FROM to_add;

DELETE FROM repository
WHERE
  ROWID IN (
    SELECT
      r.ROWID
    FROM
      repository AS r
      INNER JOIN to_remove USING (groupId, artifactId, version)
  );

DELETE FROM to_remove;
