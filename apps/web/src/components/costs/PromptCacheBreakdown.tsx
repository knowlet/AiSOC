import type { CacheCostTelemetry } from '@/lib/api';

function componentValue(value: number | undefined, reported: number, currency = false): string {
  if (reported === 0 || value === undefined || !Number.isFinite(value)) return 'not reported';
  if (!currency) return `${value.toLocaleString()} tokens`;
  if (value > 0 && value < 0.000001) return '<$0.000001';
  return `$${value.toFixed(6)}`;
}

/** Cache portions of a model row; the caller still displays its unchanged total. */
export function PromptCacheBreakdown({ data, calls }: { data: CacheCostTelemetry; calls: number }) {
  const parts = [
    {
      label: 'Cache read',
      tokens: data.total_cache_read_tokens,
      tokenCalls: data.cache_read_token_call_count ?? 0,
      cost: data.cache_read_cost_usd,
      costCalls: data.cache_read_cost_call_count ?? 0,
    },
    {
      label: 'Cache write',
      tokens: data.total_cache_creation_tokens,
      tokenCalls: data.cache_creation_token_call_count ?? 0,
      cost: data.cache_creation_cost_usd,
      costCalls: data.cache_creation_cost_call_count ?? 0,
    },
  ];

  return (
    <dl className="min-w-[215px] space-y-2 text-left text-[11px]" aria-label="Prompt cache breakdown">
      {parts.map((part) => (
        <div key={part.label}>
          <dt className="font-medium text-slate-300">{part.label}</dt>
          <dd className="text-slate-400 tabular-nums">
            {componentValue(part.tokens, part.tokenCalls)} · {part.tokenCalls}/{calls} calls
          </dd>
          <dd className="text-slate-400 tabular-nums">
            {componentValue(part.cost, part.costCalls, true)} · {part.costCalls}/{calls} calls
          </dd>
        </div>
      ))}
    </dl>
  );
}
