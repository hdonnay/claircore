INSERT INTO
  import.artifact (groupId, artifactId)
VALUES
  (?, ?)
ON CONFLICT DO NOTHING;
