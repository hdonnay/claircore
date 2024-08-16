SELECT
	"id",
	"name",
	"ref",
	"date",
	"success",
	"fingerprint"::BYTEA,
	"error"
FROM
	updater_v1.run
	JOIN updater_v1.updater ON updater.id = run.updater
WHERE
	id > $2
LIMIT $1
ORDER BY
	(date,
		id) ASC;
