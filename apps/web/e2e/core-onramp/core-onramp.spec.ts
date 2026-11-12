import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { expect, test, type Page } from '@playwright/test';

// Run after `make demo` on the real CORE stack. This suite does not stub
// routes, inject sessions, start an investigation, or invoke a hosted model.
// These screenshots contain the explicitly seeded synthetic corpus, not
// evidence of a real incident or of model quality.
const artifacts = process.env.AISOC_ONRAMP_ARTIFACTS ?? '';
const showcase = '/cases/INC-RT-001';

async function signIn(page: Page, destination: string) {
  await page.goto(`/login?next=${encodeURIComponent(destination)}`);
  await page.getByLabel('Email').fill('demo@example.com');
  await page.getByLabel('Password').fill('aisoc-demo');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page).toHaveURL(new URL(destination, 'http://localhost:3000').href);
}

async function screenshot(page: Page, name: string) {
  if (!artifacts) throw new Error('Set AISOC_ONRAMP_ARTIFACTS to retain real-stack evidence');
  await mkdir(artifacts, { recursive: true });
  await page.screenshot({ path: path.join(artifacts, `${name}.png`), fullPage: true });
}

test.beforeEach(async ({ baseURL }) => {
  // This test uses the public demo credential and belongs on an ephemeral
  // runner, never an operator's deployed instance.
  expect(baseURL).toBe('http://localhost:3000');
  if (!artifacts) throw new Error('AISOC_ONRAMP_ARTIFACTS is required');
  await mkdir(artifacts, { recursive: true });
});

test.afterEach(async ({ page }, testInfo) => {
  if (testInfo.status !== testInfo.expectedStatus) {
    await screenshot(page, `synthetic-failure-${testInfo.title.replace(/[^a-z0-9]+/gi, '-')}`);
  }
});

test('seeded synthetic case has a visible persistent investigation ledger', async ({ page }) => {
  const caseResponsePromise = page.waitForResponse(response =>
    new URL(response.url()).pathname === `/api/v1${showcase}` && response.request().method() === 'GET',
  );
  await signIn(page, showcase);
  const caseResponse = await caseResponsePromise;
  expect(caseResponse.status()).toBe(200);
  const caseRecord = await caseResponse.json();
  expect(caseRecord.case_number).toBe('INC-RT-001');
  await expect(page.getByRole('heading', {
    name: 'LockBit 3.0 ransomware lateral spread on WIN-FIN-DB01',
  })).toBeVisible();

  // The README and issue #353 promise visible synthetic provenance. Do not
  // infer it from a filename, enable demo fallback, or invent an API field.
  await expect.soft(page.getByText(/synthetic|demo data/i).first(),
    'The seeded case must visibly identify its synthetic provenance',
  ).toBeVisible();

  const runsResponsePromise = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.pathname === '/api/v1/investigations' && url.searchParams.has('case_id');
  });
  await page.getByRole('button', { name: /^Ledger/ }).click();
  const runsResponse = await runsResponsePromise;
  expect(runsResponse.status()).toBe(200);
  const runs = await runsResponse.json();
  expect(Array.isArray(runs)).toBe(true);
  await writeFile(path.join(artifacts, 'synthetic-ledger-observation.json'), JSON.stringify({
    commit: process.env.AISOC_TEST_COMMIT,
    provenance: 'Explicit make demo seed on an ephemeral real CORE stack',
    case_id: caseRecord.id,
    case_number: caseRecord.case_number,
    case_tags: caseRecord.tags,
    ledger_case_filter: new URL(runsResponse.url()).searchParams.get('case_id'),
    runs: runs.map((run: { id: string; case_id: string }) => ({ id: run.id, case_id: run.case_id })),
  }, null, 2));
  expect(runs.length, 'The documented showcase must expose its seeded run through the actual UI query').toBeGreaterThan(0);

  await expect(page.getByLabel('Filter by event kind')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Export', exact: true })).toBeVisible();
  await expect(page.locator('[data-seq]').first()).toBeVisible();
  await expect(page.locator('[data-seq="1"]')).toContainText('Enumerated active processes on WIN-FIN-DB01');
  await screenshot(page, 'synthetic-showcase-ledger');
});

// Separate from the documented demo walk-through so an existing seed/ledger
// defect does not prevent reviewing the BYOK change against the real API.
test('BYOK model guidance distinguishes hosted defaults from endpoint identifiers', async ({ page }) => {
  await signIn(page, '/settings?tab=deployment');
  await page.getByRole('button', { name: 'Configure BYOK', exact: true }).click();
  await page.getByRole('combobox', { name: 'Provider', exact: true }).selectOption('openai');
  await expect(page.getByPlaceholder('provider default')).toBeVisible();
  await expect(page.getByText('Provider-specific identifier. Leave blank for the selected provider default.')).toBeVisible();
  await screenshot(page, 'synthetic-tenant-byok-hosted');

  await page.getByRole('combobox', { name: 'Provider', exact: true }).selectOption('local-ollama');
  await expect(page.getByPlaceholder('model, deployment, or gateway alias')).toBeVisible();
  await expect(page.getByText('Enter the model served by this endpoint, its deployment name, or a gateway alias.')).toBeVisible();
  await screenshot(page, 'synthetic-tenant-byok-local');
});
