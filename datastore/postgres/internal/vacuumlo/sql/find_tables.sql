SELECT
  s.nspname,
  c.relname,
  a.attname
FROM
  pg_class c,
  pg_attribute a,
  pg_namespace s,
  pg_type t
WHERE
  a.attnum > 0
  AND NOT a.attisdropped
  AND a.attrelid = c.oid
  AND a.atttypid = t.oid
  AND c.relnamespace = s.oid
  AND t.typname in ('oid', 'lo')
  AND c.relkind in ('r', 'm')
  AND s.nspname !~ '^pg_';
