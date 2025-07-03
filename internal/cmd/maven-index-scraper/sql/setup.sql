CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS artifact (
  id INTEGER PRIMARY KEY ASC, -- alias for rowid
  groupId TEXT NOT NULL,
  artifactId TEXT NOT NULL,
  UNIQUE (groupId, artifactId)
);

CREATE TABLE IF NOT EXISTS lookup (
  artifact INTEGER REFERENCES artifact (id) NOT NULL,
  version TEXT NOT NULL,
);

PRAGMA journal_mode = MEMORY;

PRAGMA locking_mode = EXCLUSIVE;

PRAGMA optimize = 0x10002;
