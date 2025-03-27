CREATE TEMP TABLE vacuum_l AS
SELECT
  oid AS lo
FROM
  pg_largeobject_metadata;
