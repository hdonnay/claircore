INSERT OR REPLACE INTO
  lookup (artifact, version, sha1)
SELECT
  artifact.id,
  :version,
  :sha1
FROM
  artifact
WHERE
  groupId = :groupId
  AND artifactId = :artifactId
