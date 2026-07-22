CREATE TABLE vti_seen_categories (
 category text PRIMARY KEY,
 occurrences bigint NOT NULL DEFAULT 0,
 max_score integer NOT NULL,
 first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL
);

INSERT INTO vti_seen_categories(category,occurrences,max_score,first_seen,last_seen)
SELECT coalesce(d.category,'Uncategorized'),count(*)::bigint,max(o.score)::integer,min(o.observed_at),max(o.observed_at)
FROM vti_observations o JOIN vti_definitions d ON d.id=o.vti_definition_id
WHERE o.score>=3 GROUP BY coalesce(d.category,'Uncategorized')
ON CONFLICT(category) DO UPDATE SET occurrences=EXCLUDED.occurrences,max_score=EXCLUDED.max_score,
 first_seen=EXCLUDED.first_seen,last_seen=EXCLUDED.last_seen;
