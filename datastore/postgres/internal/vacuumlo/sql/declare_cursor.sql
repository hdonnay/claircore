DECLARE myportal CURSOR
WITH
  HOLD FOR
SELECT
  lo
FROM
  vacuum_l;
