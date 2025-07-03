-- Assign any new artifact IDs needed.
INSERT INTO
  artifact (groupId, artifactId)
SELECT
  groupId,
  artifactId
FROM
  todo
WHERE
  addition = TRUE
ON CONFLICT DO NOTHING;

-- Issue any deletes corresponding to removals.
--
-- Removals within the queued chunk should already be "done" because a later
-- removal overwrote the addiiton, and the lone removal record just gets ignored here.
DELETE FROM lookup
WHERE
  rowid IN (
    SELECT
      lookup.rowid
    FROM
      todo
      JOIN artifact USING (groupId, artifactId)
      JOIN lookup ON (
        lookup.artifact = artifact.id
        AND lookup.version = todo.version
      )
    WHERE
      todo.addition = FALSE
  );

-- Insert net-new lookup entries.
INSERT INTO
  lookup (artifact, version, sha1)
SELECT
  artifact.id,
  todo.version,
  todo.sha1
FROM
  todo
  JOIN artifact USING (groupId, artifactId)
WHERE
  todo.addition = TRUE
ON CONFLICT (sha1) DO NOTHING;

DELETE FROM todo;

PRAGMA optimize;
