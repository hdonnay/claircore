SELECT
	EXISTS (
		SELECT
			1
		FROM
			matcher_v2.run
		WHERE
			complete
		LIMIT 1);
