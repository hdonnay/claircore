INSERT INTO artifact (groupId, artifactId) VALUES (?1 ,?2) ON CONFLICT DO NOTHING;
SELECT id FROM artifact WHERE groupId = ?1 AND artifactId = ?2;
