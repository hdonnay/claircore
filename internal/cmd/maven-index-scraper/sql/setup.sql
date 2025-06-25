CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS repository (
  groupId TEXT NOT NULL,
  artifactId TEXT NOT NULL,
  version TEXT NOT NULL,
  sha1 BLOB UNIQUE,
  sha256 BLOB UNIQUE,
  UNIQUE (groupId, artifactId, version)
);

CREATE TEMPORARY TABLE to_add (
  groupId TEXT NOT NULL,
  artifactId TEXT NOT NULL,
  version TEXT NOT NULL,
  sha1 BLOB,
  sha256 BLOB
);

CREATE TEMPORARY TABLE to_remove (
  groupId TEXT NOT NULL,
  artifactId TEXT NOT NULL,
  version TEXT NOT NULL
);

PRAGMA journal_mode = MEMORY;

PRAGMA locking_mode = EXCLUSIVE;
