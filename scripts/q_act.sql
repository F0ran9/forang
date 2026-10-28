SELECT pid, state, wait_event_type, wait_event, now()-query_start AS dur, left(query,70) FROM pg_stat_activity WHERE query ILIKE '%pocs%' OR query ILIKE '%INSERT%' ORDER BY query_start LIMIT 6;
