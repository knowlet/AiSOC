/**
 * Alert Volume's interval selector controls the dashboard metrics request.
 * Keep its polling behavior, persistence, and manual refresh covered together:
 * a dropdown that only changes its label is not a refresh control.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { hydrateRoot } from 'react-dom/client';
import { renderToString } from 'react-dom/server';

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
const originalLocalStorage = Object.getOwnPropertyDescriptor(window, 'localStorage')!;
const originalSessionStorage = Object.getOwnPropertyDescriptor(window, 'sessionStorage')!;
let storageFrame: HTMLIFrameElement | undefined;

function intervalSelect(): HTMLSelectElement {
  return screen.getByRole('combobox', { name: /Auto-refresh/i }) as HTMLSelectElement;
}

function lastDashboardPoll() {
  const call = swrCalls.at(-1);
  if (!call) throw new Error('The dashboard never configured its metrics poll');
  return call;
}

beforeEach(() => {
  // The shared setup uses one plain-object shim for both storage areas. Use
  // distinct native Storage objects so failure spies and StorageEvent exercise
  // the browser API, including its storageArea identity check.
  storageFrame = document.createElement('iframe');
  document.body.appendChild(storageFrame);
  const storageWindow = storageFrame.contentWindow;
  if (!storageWindow) throw new Error('Could not create a native storage window');
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    value: storageWindow.localStorage,
  });
  Object.defineProperty(window, 'sessionStorage', {
    configurable: true,
    value: storageWindow.sessionStorage,
  });
  window.localStorage.clear();
  window.sessionStorage.clear();
  swrCalls.length = 0;
  revalidateMetrics.mockClear();
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  Object.defineProperty(window, 'localStorage', originalLocalStorage);
  Object.defineProperty(window, 'sessionStorage', originalSessionStorage);
  storageFrame?.remove();
});

describe('Dashboard Alert Volume auto-refresh', () => {
  it('defaults to the existing 60-second metrics poll and offers bounded options', () => {
    render(<DashboardView />);
    expect(intervalSelect().value).toBe('60000');
    expect(lastDashboardPoll().refreshInterval).toBe(60_000);
    expect(intervalSelect()).toHaveAccessibleDescription(
      'Refreshes Alert Volume, the dashboard summary metrics, Severity Breakdown, Top MITRE ATT&CK Tactics, and Connected Sources. Does not change the time window or ingest rate.',
    );
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

  it('keeps the live selection when a storage write fails but an older value is still readable', () => {
    window.localStorage.setItem(STORAGE_KEY, '300000');
    const { rerender } = render(<DashboardView />);
    expect(intervalSelect().value).toBe('300000');

    vi.spyOn(Object.getPrototypeOf(window.localStorage) as Storage, 'setItem').mockImplementation(() => {
      throw new Error('Storage quota exceeded');
    });

    fireEvent.change(intervalSelect(), { target: { value: '15000' } });
    rerender(<DashboardView />);

    expect(intervalSelect().value).toBe('15000');
    expect(lastDashboardPoll().refreshInterval).toBe(15_000);
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe('300000');
  });

  it('supports interval changes and manual refresh when storage reads and writes are unavailable', () => {
    vi.spyOn(Object.getPrototypeOf(window.localStorage) as Storage, 'getItem').mockImplementation(() => {
      throw new Error('Storage access denied');
    });
    vi.spyOn(Object.getPrototypeOf(window.localStorage) as Storage, 'setItem').mockImplementation(() => {
      throw new Error('Storage access denied');
    });

    const { rerender } = render(<DashboardView />);
    expect(intervalSelect().value).toBe('60000');

    fireEvent.change(intervalSelect(), { target: { value: '15000' } });
    rerender(<DashboardView />);
    expect(intervalSelect().value).toBe('15000');
    expect(lastDashboardPoll().refreshInterval).toBe(15_000);

    fireEvent.change(intervalSelect(), { target: { value: '0' } });
    expect(intervalSelect().value).toBe('0');
    expect(lastDashboardPoll().refreshInterval).toBe(0);
    expect(lastDashboardPoll().revalidateOnReconnect).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: /Refresh now/i }));
    expect(revalidateMetrics).toHaveBeenCalledTimes(1);
  });

  it('hydrates the default server markup before restoring the saved client interval', async () => {
    window.localStorage.setItem(STORAGE_KEY, '15000');
    const container = document.createElement('div');
    container.innerHTML = renderToString(<DashboardView />);
    document.body.appendChild(container);
    const onRecoverableError = vi.fn();
    let root: ReturnType<typeof hydrateRoot> | undefined;

    try {
      expect(intervalSelect().value).toBe('60000');
      expect(lastDashboardPoll().refreshInterval).toBe(60_000);

      await act(async () => {
        root = hydrateRoot(container, <DashboardView />, { onRecoverableError });
      });

      expect(intervalSelect().value).toBe('15000');
      expect(lastDashboardPoll().refreshInterval).toBe(15_000);
      expect(onRecoverableError).not.toHaveBeenCalled();
    } finally {
      await act(async () => { root?.unmount(); });
      container.remove();
    }
  });

  it('handles another tab changing, invalidating, or clearing the saved interval', () => {
    render(<DashboardView />);

    window.localStorage.setItem(STORAGE_KEY, '30000');
    fireEvent(window, new StorageEvent('storage', {
      key: STORAGE_KEY,
      newValue: '30000',
      storageArea: window.localStorage,
    }));
    expect(intervalSelect().value).toBe('30000');
    expect(lastDashboardPoll().refreshInterval).toBe(30_000);

    window.localStorage.setItem(STORAGE_KEY, 'invalid');
    fireEvent(window, new StorageEvent('storage', {
      key: STORAGE_KEY,
      newValue: 'invalid',
      storageArea: window.localStorage,
    }));
    expect(intervalSelect().value).toBe('60000');
    expect(lastDashboardPoll().refreshInterval).toBe(60_000);

    window.localStorage.setItem(STORAGE_KEY, '0');
    fireEvent(window, new StorageEvent('storage', {
      key: STORAGE_KEY,
      newValue: '0',
      storageArea: window.localStorage,
    }));
    expect(lastDashboardPoll().refreshInterval).toBe(0);

    window.localStorage.clear();
    fireEvent(window, new StorageEvent('storage', {
      key: null,
      storageArea: window.localStorage,
    }));
    expect(intervalSelect().value).toBe('60000');
    expect(lastDashboardPoll().refreshInterval).toBe(60_000);
  });

  it('ignores storage events for unrelated keys and session storage', () => {
    render(<DashboardView />);
    window.localStorage.setItem(STORAGE_KEY, '15000');
    window.sessionStorage.setItem(STORAGE_KEY, '30000');

    fireEvent(window, new StorageEvent('storage', {
      key: STORAGE_KEY,
      newValue: '30000',
      storageArea: window.sessionStorage,
    }));
    expect(intervalSelect().value).toBe('60000');
    expect(lastDashboardPoll().refreshInterval).toBe(60_000);

    fireEvent(window, new StorageEvent('storage', {
      key: 'unrelated-setting',
      newValue: 'changed',
      storageArea: window.localStorage,
    }));
    expect(intervalSelect().value).toBe('60000');
    expect(lastDashboardPoll().refreshInterval).toBe(60_000);

    fireEvent(window, new StorageEvent('storage', {
      key: STORAGE_KEY,
      newValue: '15000',
      storageArea: window.localStorage,
    }));
    expect(intervalSelect().value).toBe('15000');
    expect(lastDashboardPoll().refreshInterval).toBe(15_000);
  });
});
