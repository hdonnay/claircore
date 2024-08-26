SELECT
  CASE $1::TEXT
    WHEN 'libvuln_migrations' THEN (
      SELECT
        max(version)
      FROM
        "libvuln_migrations"
    )
    ELSE NULL
  END;
