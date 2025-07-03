DELETE FROM lookup
WHERE
  ROWID IN (
    SELECT
      lookup.ROWID
    FROM
      lookup
      JOIN artifact ON (artifact.id = lookup.artifact)
    WHERE
      lookup.version = :version
      AND artifact.groupId = :groupId
      AND artifact.artifactId = :artifactId
  )
