-- Cache usage and gateway-reported cost components for investigation telemetry.
-- Components are already included in measured_cost_usd; never add them to it.
-- Coverage counts distinguish reported zero from absent metadata, including
-- every row written before this migration. Historical totals remain unchanged.

ALTER TABLE aisoc_run_costs
    ADD COLUMN IF NOT EXISTS total_cache_read_tokens BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS total_cache_creation_tokens BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS cache_read_token_call_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS cache_creation_token_call_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS cache_read_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS cache_creation_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS cache_read_cost_call_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS cache_creation_cost_call_count INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN aisoc_run_costs.total_cache_read_tokens IS
    'Cached input tokens read, already included in total_prompt_tokens. '
    'Read with cache_read_token_call_count; 0 coverage means not reported.';
COMMENT ON COLUMN aisoc_run_costs.total_cache_creation_tokens IS
    'Input tokens written to the provider prompt cache, already included in '
    'total_prompt_tokens. Read with cache_creation_token_call_count.';
COMMENT ON COLUMN aisoc_run_costs.cache_read_cost_usd IS
    'Gateway-reported cache-read cost, already included in measured_cost_usd. '
    'Read with cache_read_cost_call_count; never add this component to the total.';
COMMENT ON COLUMN aisoc_run_costs.cache_creation_cost_usd IS
    'Gateway-reported cache-write cost, already included in measured_cost_usd. '
    'Read with cache_creation_cost_call_count; never add this component to the total.';
