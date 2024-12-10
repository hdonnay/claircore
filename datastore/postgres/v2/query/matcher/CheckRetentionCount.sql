SELECT COALESCE((config -> 'retain_runs')::INTEGER, 1) FROM matcher_v2_meta.latest_config ();
