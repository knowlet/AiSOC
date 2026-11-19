/**
 * Alert Volume's interval selector controls the dashboard metrics request.
 * Keep its polling behavior, persistence, and manual refresh covered together:
 * a dropdown that only changes its label is not a refresh control.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

const swrCalls = vi.hoisted(() => [] as Array<{
  key: unknown;
  refreshInterval?: number;
  revalidateOnReconnect?: boolean;
}>);
const revalidateMetrics = vi.hoisted(() => vi.fn());

vi.mock('swr', () => ({
  __esModule: true,
  default: (
    key: unknown,
    _fetcher: unknown,
    options?: { refreshInterval?: number; revalidateOnReconnect?: boolean },
  ) => {
    if (Array.isArray(key) && key[0] === 'dashboard-metrics') {
      swrCalls.push({
        key,
        refreshInterval: options?.refreshInterval,
        revalidateOnReconnect: options?.revalidateOnReconnect,
      });
    }
    return { data: undefined, error: undefined, isLoading: true, mutate: revalidateMetrics };
  },
}));

vi.mock('@/components/layout/TimeWindowProvider', () => ({
  useTimeWindow: () => ({ window: '24h' }),
}));

vi.mock('@/lib/api', () => ({
  metricsApi: { getDashboard: vi.fn(() => Promise.resolve({})) },
}));
vi.mock('@/lib/demoFallback', () => ({ demoFallback: () => undefined }));
vi.mock('next/dynamic', () => ({
  __esModule: true,
  default: () => function ChartStub() { return null; },
}));
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a>,
}));

// The other dashboard sections have independent polling and are not part of
// the /metrics/dashboard interval. Isolate this control from their requests.
vi.mock('./LiveFeedPanel', () => ({ LiveFeedPanel: () => null }));
vi.mock('./SOCMetricsDashboard', () => ({ SOCMetricsDashboard: () => null }));
vi.mock('./DashboardWelcome', () => ({ DashboardWelcome: () => null }));
vi.mock('./FunnelKpiBar', () => ({ FunnelKpiBar: () => null }));
vi.mock('./EfficiencyReport', () => ({ EfficiencyReport: () => null }));
vi.mock('./PipelineHealth', () => ({ PipelineHealth: () => null }));

import { DashboardView } from './DashboardView';

const STORAGE_KEY = 'aisoc:dashboard:refresh-interval';

function intervalSelect(): HTMLSelectElement {
  return screen.getByRole('combobox', { name: /Auto-refresh/i }) as HTMLSelectElement;
}

function lastDashboardPoll() {
  const call = swrCalls.at(-1);
  if (!call) throw new Error('The dashboard never configured its metrics poll');
  return call;
}

beforeEach(() => {
  window.localStorage.clear();
  swrCalls.length = 0;
  revalidateMetrics.mockClear();
});

afterEach(() => { cleanup(); });

describe('Dashboard Alert Volume auto-refresh', () => {
  it('defaults to the existing 60-second metrics poll and offers bounded options', () => {
    render(<DashboardView />);
    expect(intervalSelect().value).toBe('60000');
    expect(lastDashboardPoll().refreshInterval).toBe(60_000);
    expect(Array.from(intervalSelect().options, (option) => option.value)).toEqual([
      '0', '15000', '30000', '60000', '300000',
    ]);
  });

  it('changes the live SWR interval without changing the period cache key, then restores it after remount', () => {
    const { unmount } = render(<DashboardView />);
    const originalKey = lastDashboardPoll().key;

    fireEvent.change(intervalSelect(), { target: { value: '15000' } });

    expect(intervalSelect().value).toBe('15000');
    expect(lastDashboardPoll().refreshInterval).toBe(15_000);
    expect(lastDashboardPoll().key).toEqual(originalKey);
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe('15000');

    unmount();
    render(<DashboardView />);

    expect(intervalSelect().value).toBe('15000');
    expect(lastDashboardPoll().refreshInterval).toBe(15_000);
  });

  it('rejects unsupported stored intervals instead of turning bad data into a polling schedule', () => {
    window.localStorage.setItem(STORAGE_KEY, '100');
    render(<DashboardView />);

    expect(intervalSelect().value).toBe('60000');
    expect(lastDashboardPoll().refreshInterval).toBe(60_000);
  });

  it('can disable timed polling while keeping manual refresh available', () => {
    render(<DashboardView />);

    fireEvent.change(intervalSelect(), { target: { value: '0' } });
    expect(lastDashboardPoll().refreshInterval).toBe(0);
    expect(lastDashboardPoll().revalidateOnReconnect).toBe(false);
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe('0');

    fireEvent.click(screen.getByRole('button', { name: /Refresh now/i }));
    expect(revalidateMetrics).toHaveBeenCalledTimes(1);
  });
});
