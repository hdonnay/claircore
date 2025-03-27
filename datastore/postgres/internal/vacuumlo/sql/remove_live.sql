DELETE FROM vacuum_l WHERE lo IN (SELECT %s FROM %s.%s);
