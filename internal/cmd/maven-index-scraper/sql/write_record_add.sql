INSERT INTO lookup (artifact, version, sha1)
VALUES
  (?, ?, ?)
	ON CONFLICT (sha1) DO UPDATE SET version = excluded.version
