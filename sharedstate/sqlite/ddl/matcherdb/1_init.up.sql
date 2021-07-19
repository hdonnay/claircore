CREATE TABLE updater (
	id INTEGER,
	updater TEXT NOT NULL,
	UNIQUE(updater) ON CONFLICT IGNORE,
	PRIMARY KEY(id ASC)
);

CREATE TABLE update_operation (
	id INTEGER,
	ref TEXT NOT NULL,
	updater INTEGER REFERENCES updater (id) ON DELETE CASCADE,
	fingerprint BLOB,
	kind TEXT NOT NULL,
	time TEXT NOT NULL DEFAULT (datetime('now')),
	PRIMARY KEY(id ASC)
);

CREATE TABLE vulnerability (
	id INTEGER,
	digest_kind TEXT NOT NULL,
	digest BLOB NOT NULL,
	updater INTEGER REFERENCES updater (id) ON DELETE CASCADE,
	package INTEGER REFERENCES package (id) ON UPDATE CASCADE,
	distro INTEGER REFERENCES distro (id) ON UPDATE CASCADE,
	repo INTEGER REFERENCES repo (id) ON UPDATE CASCADE,
	name TEXT,
	description TEXT,
	issued TEXT, -- timestamp
	severity TEXT,
	normalized_severity TEXT,
	fixed_in_version TEXT,
	arch_operation TEXT,
	UNIQUE (digest_kind, digest) ON CONFLICT IGNORE,
	PRIMARY KEY(id ASC)
);

CREATE TABLE package (
	id INTEGER,
	name TEXT,
	version TEXT,
	module TEXT,
	arch TEXT,
	kind TEXT,
	PRIMARY KEY(id ASC)
);

CREATE TABLE distro (
	id INTEGER,
	ident TEXT,
	name TEXT,
	version TEXT,
	version_code_name TEXT,
	version_id TEXT,
	arch TEXT,
	cpe TEXT,
	pretty_name TEXT,
	PRIMARY KEY(id ASC)
);

CREATE TABLE repo (
	id INTEGER,
	name TEXT,
	key TEXT,
	uri TEXT,
	PRIMARY KEY(id ASC)
);

-- Some databases like to control the links to namespaces they don't own,
-- watch out for that.
CREATE TABLE link (
	id INTEGER,
	source TEXT NOT NULL,
	ref TEXT NOT NULL,
	url TEXT,
	UNIQUE(source, ref) ON CONFLICT REPLACE,
	PRIMARY KEY(id ASC)
);

CREATE TABLE vulnerability_link (
	vulnerability REFERENCES vulnerability (id) ON DELETE CASCADE,
	link REFERENCES link (id) ON DELETE CASCADE,
	UNIQUE(vulnerability, link) ON CONFLICT IGNORE
);

CREATE TABLE update_operation_vulnerability (
	update_operation REFERENCES update_operation (id) ON DELETE CASCADE,
	vulnerability REFERENCES vulnerability (id) ON DELETE CASCADE,
	UNIQUE(update_operation, vulnerability) ON CONFLICT IGNORE
);
CREATE INDEX update_operation_vulnerability_update_operation ON update_operation_vulnerability (update_operation);
CREATE INDEX update_operation_vulnerability_vulnerability ON update_operation_vulnerability (vulnerability);

CREATE TABLE enrichment (
	id INTEGER,
	digest_kind TEXT NOT NULL,
	digest BLOB NOT NULL,
	updater INTEGER REFERENCES updater (id) ON DELETE CASCADE,
	tags TEXT NOT NULL, -- concatenated with commas
	data TEXT NOT NULL, -- sqlite handles json as text
	UNIQUE (digest_kind, digest) ON CONFLICT IGNORE,
	PRIMARY KEY(id ASC)
);

CREATE TABLE update_operation_enrichment (
	update_operation REFERENCES update_operation (id) ON DELETE CASCADE,
	enrichment REFERENCES enrichment (id) ON DELETE CASCADE,
	UNIQUE(update_operation, enrichment) ON CONFLICT IGNORE
);
