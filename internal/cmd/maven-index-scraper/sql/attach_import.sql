ATTACH DATABASE ':memory:' AS import;

CREATE TABLE IF NOT EXISTS import.artifact (
  id INTEGER PRIMARY KEY ASC, -- alias for rowid
  groupId TEXT NOT NULL,
  artifactId TEXT NOT NULL,
  UNIQUE (groupId, artifactId)
);

CREATE TABLE IF NOT EXISTS import.lookup (
  artifact INTEGER REFERENCES artifact (id) NOT NULL,
  version TEXT NOT NULL,
);
