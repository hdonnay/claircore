SELECT
  setting
FROM
  pg_settings
WHERE
  name = 'work_mem';
