INSERT INTO
  artifact (groupId, artifactId)
VALUES
  (:groupId, :artifactId)
ON CONFLICT DO NOTHING;
