SELECT
  ROW (
    u.name,
    ur.ref,
    run.date,
    ur.success,
    ur.fingerprint,
    ur.error
  )
FROM
  matcher_v2.updater_run AS ur
  JOIN matcher_v2.updater AS u ON u.id = ur.updater
  JOIN matcher_v2.run AS run ON run.id = ur.run
WHERE
  u.id = $1
  AND ur.id < $2
ORDER BY
  ur.id ASC
LIMIT
  1;
