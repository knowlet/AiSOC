import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import type { LedgerModelCost, LedgerRunDetail } from '@/lib/api';

const responses = vi.hoisted(() => new Map<string, unknown>());
vi.mock('swr', () => ({
  default: (key: unknown) => ({
    data: responses.get(JSON.stringify(key)),
    isLoading: false,
    mutate: vi.fn(),
  }),
}));
vi.mock('@/lib/api', () => ({ ledgerApi: {} }));

import { InvestigationLedger } from './InvestigationLedger';

const baseModel: LedgerModelCost = {
  model: 'aisoc-investigation',
  resolved_model: 'gateway-model',
  total_prompt_tokens: 10000,
  total_completion_tokens: 500,
  total_cost_usd: 0.02,
  measured_call_count: 3,
  estimated_cost_usd: 0,
  estimated_call_count: 0,
  unpriced_call_count: 0,
  total_latency_ms: 120,
  call_count: 3,
};

function show(model: LedgerModelCost) {
  const run: LedgerRunDetail = {
    id: 'cache-run',
    case_id: 'cache-case',
    status: 'completed',
    model_used: 'gateway-model',
    iterations: 3,
    total_tokens: 10500,
    total_cost_usd: 0.02,
    measured_call_count: 3,
    estimated_cost_usd: 0,
    estimated_call_count: 0,
    unpriced_call_count: 0,
    started_at: '2026-11-24T12:00:00Z',
    completed_at: '2026-11-24T12:01:00Z',
    error: null,
    alert_summary: 'Authored cost regression fixture',
    event_count: 0,
    artifact_count: 0,
    model_costs: [model],
  };
  responses.set(JSON.stringify(['ledger.runs', run.case_id]), [run]);
  responses.set(JSON.stringify(['ledger.run', run.id]), run);
  responses.set(JSON.stringify(['ledger.events', run.id]), []);
  render(<InvestigationLedger caseId={run.case_id} activeRunId={run.id} />);
  return within(screen.getByRole('table'));
}

beforeEach(() => responses.clear());

describe('Investigation ledger prompt-cache costs', () => {
  it('shows components and independent coverage while preserving the gateway total', () => {
    const table = show({
      ...baseModel,
      total_cache_read_tokens: 8000,
      total_cache_creation_tokens: 1000,
      cache_read_token_call_count: 3,
      cache_creation_token_call_count: 2,
      cache_read_cost_usd: 0.0006,
      cache_creation_cost_usd: 0.001,
      cache_read_cost_call_count: 2,
      cache_creation_cost_call_count: 1,
    });
    expect(table.getByText('8,000 tokens · 3/3 calls')).toBeInTheDocument();
    expect(table.getByText('1,000 tokens · 2/3 calls')).toBeInTheDocument();
    expect(table.getByText('$0.000600 · 2/3 calls')).toBeInTheDocument();
    expect(table.getByText('$0.001000 · 1/3 calls')).toBeInTheDocument();
    expect(table.getByText('$0.0200')).toBeInTheDocument();
    expect(table.queryByText('$0.0216')).not.toBeInTheDocument();
    expect(screen.getByText(/Reported cache costs are already included/)).toBeInTheDocument();
  });

  it('keeps an older server payload unknown instead of reporting free caching', () => {
    const table = show(baseModel);
    expect(table.getAllByText('not reported · 0/3 calls')).toHaveLength(4);
    expect(table.queryByText(/\$0\.000000/)).not.toBeInTheDocument();
  });

  it('distinguishes an observed zero from an unreported write cost', () => {
    const table = show({
      ...baseModel,
      total_cache_read_tokens: 0,
      cache_read_token_call_count: 3,
      cache_read_cost_usd: 0,
      cache_read_cost_call_count: 3,
    });
    expect(table.getByText('0 tokens · 3/3 calls')).toBeInTheDocument();
    expect(table.getByText('$0.000000 · 3/3 calls')).toBeInTheDocument();
    expect(table.getAllByText('not reported · 0/3 calls')).toHaveLength(2);
  });

  it('does not round a positive reported cache component down to zero', () => {
    const table = show({ ...baseModel, cache_read_cost_usd: 0.00000001, cache_read_cost_call_count: 1 });
    expect(table.getByText('<$0.000001 · 1/3 calls')).toBeInTheDocument();
  });
});
