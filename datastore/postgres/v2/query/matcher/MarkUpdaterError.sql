UPDATE matcher_v2.updater_run
SET
  error = $2
WHERE
  id = $1;
