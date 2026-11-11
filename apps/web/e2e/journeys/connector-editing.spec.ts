import { expect, test, type Page } from "@playwright/test";
import type { ConnectorCatalogEntry } from "../../src/lib/api";

// Synthetic fixtures exist only at the HTTP boundary. The route, client,
// schema-driven form and cache update all run in the real Next.js app.
const CONNECTOR_ID = "11111111-1111-4111-8111-111111111111";
const CONNECTOR_PATH = `/api/v1/connectors/${CONNECTOR_ID}`;
const FIXTURE_NAME = "Synthetic test fixture Wazuh";

const SCHEMA: ConnectorCatalogEntry = {
  connector_id: "wazuh",
  connector_name: "Wazuh",
  category: "siem",
  description: "Synthetic Wazuh fixture for browser tests",
  fields: [
    { name: "indexer_url", type: "string", label: "Wazuh Indexer URL", required: true },
    { name: "username", type: "string", label: "Indexer Username", required: true },
    { name: "password", type: "secret", label: "Indexer Password", required: true },
    {
      name: "index_pattern",
      type: "string",
      label: "Alert Index Pattern",
      default: "wazuh-alerts-*",
    },
    { name: "min_rule_level", type: "number", label: "Minimum Rule Level", default: 7 },
    { name: "verify_tls", type: "boolean", label: "Verify TLS Certificate", default: true },
    {
      name: "vuln_mode",
      type: "select",
      label: "Vulnerability Events",
      default: "inventory",
      options: [
        { value: "inventory", label: "Inventory" },
        { value: "alerts", label: "Alerts" },
      ],
    },
  ],
};

async function stubConnectorApi(page: Page) {
  let row = {
    id: CONNECTOR_ID,
    tenant_id: "22222222-2222-4222-8222-222222222222",
    name: FIXTURE_NAME,
    connector_type: "wazuh",
    category: "siem",
    is_enabled: true,
    oauth_provisioned: false,
    connector_config: {
      indexer_url: "https://indexer.example.com",
      index_pattern: "wazuh-alerts-*",
      min_rule_level: 0,
      verify_tls: false,
      vuln_mode: "inventory",
      checkpoint: { cursor: "preserved-by-server" },
    },
    health_status: "healthy",
    last_health_check: null,
    last_sync: null,
    events_ingested: 42,
    error_count: 0,
    tags: ["synthetic-fixture"],
    created_at: "2026-11-01T00:00:00Z",
    updated_at: "2026-11-01T00:00:00Z",
  };
  const patches: Record<string, unknown>[] = [];
  const drafts: Record<string, unknown>[] = [];
  const unexpected: string[] = [];

  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();
    if (method === "GET" && path === "/api/v1/connectors") {
      await route.fulfill({ json: [row] });
    } else if (method === "GET" && path === "/api/v1/connectors/health") {
      await route.fulfill({
        json: {
          total: 1,
          healthy: 1,
          unhealthy: 0,
          unknown: 0,
          drifted: 0,
          drifted_recently: 0,
          last_drift_at: null,
          total_events_ingested: 42,
          total_events_dropped: 0,
        },
      });
    } else if (method === "GET" && path === "/api/v1/connectors/catalog") {
      await route.fulfill({ json: { connectors: [SCHEMA] } });
    } else if (method === "GET" && path === `${CONNECTOR_PATH}/edit_config`) {
      await route.fulfill({
        json: {
          connector: row,
          values: {
            indexer_url: row.connector_config.indexer_url,
            index_pattern: row.connector_config.index_pattern,
            min_rule_level: row.connector_config.min_rule_level,
            verify_tls: row.connector_config.verify_tls,
            vuln_mode: row.connector_config.vuln_mode,
            username: "reader",
          },
          configured_secret_fields: ["password"],
        },
      });
    } else if (method === "POST" && path === `${CONNECTOR_PATH}/test`) {
      drafts.push(request.postDataJSON() as Record<string, unknown>);
      await route.fulfill({
        json: { success: true, message: "Synthetic draft connection passed" },
      });
    } else if (method === "PATCH" && path === CONNECTOR_PATH) {
      const patch = request.postDataJSON() as Record<string, unknown>;
      patches.push(patch);
      row = {
        ...row,
        name: typeof patch.name === "string" ? patch.name : row.name,
        connector_config: {
          ...row.connector_config,
          ...(patch.connector_config_patch as Record<string, unknown>),
        },
      };
      await route.fulfill({ json: row });
    } else if (method === "GET" && path === "/api/v1/branding") {
      await route.fulfill({
        json: {
          product_name: "AiSOC",
          primary_color: "#3b82f6",
          accent_color: "#8b5cf6",
          support_email: null,
          support_url: null,
          sender_name: "AiSOC",
          footer_text: "",
          logo_url: null,
          org_id: null,
          is_white_labelled: false,
        },
      });
    } else if (
      method === "GET" &&
      ["/api/v1/inbox/templates", "/api/v1/inbox/tokens"].includes(path)
    ) {
      await route.fulfill({ json: [] });
    } else {
      unexpected.push(`${method} ${path}`);
      await route.fulfill({
        status: 404,
        json: { detail: "No synthetic fixture for this request" },
      });
    }
  });

  return { patches, drafts, unexpected };
}

for (const viewport of [
  { label: "desktop", width: 1440, height: 1000 },
  { label: "mobile", width: 390, height: 844 },
]) {
  test.describe(`connector editing — ${viewport.label}`, () => {
    test.use({ viewport: { width: viewport.width, height: viewport.height } });

    test("tests an unsaved draft and saves the existing connector", async ({ page }, testInfo) => {
      const api = await stubConnectorApi(page);
      await page.goto("/connectors");
      await expect(page.getByRole("heading", { name: FIXTURE_NAME, exact: true })).toBeVisible();
      await page.getByRole("button", { name: /^Configure/ }).click();

      const dialog = page.getByRole("dialog", { name: "Edit connector" });
      await expect(dialog.getByLabel("Instance name")).toHaveValue(FIXTURE_NAME);
      await expect(dialog.getByLabel("Indexer Username")).toHaveValue("reader");
      await expect(dialog.getByLabel("Minimum Rule Level")).toHaveValue("0");
      await expect(dialog.getByLabel("Verify TLS Certificate")).not.toBeChecked();
      const password = dialog.getByLabel("Indexer Password");
      await expect(password).toHaveValue("");
      await expect(password).toHaveAttribute("type", "password");
      await expect(password).toHaveAttribute("placeholder", "Leave blank to keep saved value");
      await expect(dialog.getByRole("button", { name: "Save changes" })).toBeDisabled();

      const bounds = await dialog.boundingBox();
      expect(bounds).not.toBeNull();
      expect(bounds!.x).toBeGreaterThanOrEqual(0);
      expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(viewport.width);
      expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(viewport.height);
      if (viewport.label === "mobile") {
        expect(
          await dialog
            .locator("fieldset")
            .evaluate((element) => element.scrollHeight > element.clientHeight)
        ).toBe(true);
        await dialog.getByLabel("Vulnerability Events").scrollIntoViewIfNeeded();
        await expect(dialog.getByLabel("Vulnerability Events")).toBeInViewport();
      }

      await dialog.getByLabel("Wazuh Indexer URL").fill("https://updated-indexer.example.com");
      await dialog.getByRole("button", { name: "Test connection", exact: true }).click();
      await expect(dialog.getByRole("status")).toHaveText("Synthetic draft connection passed");
      expect(api.drafts).toEqual([
        { connector_config_patch: { indexer_url: "https://updated-indexer.example.com" } },
      ]);
      expect(api.patches).toHaveLength(0);
      await expect(password).toHaveValue("");
      await expect(dialog.getByRole("button", { name: "Save changes" })).toBeInViewport();
      await expect(dialog.getByRole("button", { name: "Cancel", exact: true })).toBeInViewport();

      await password.scrollIntoViewIfNeeded();
      await page.screenshot({
        path: testInfo.outputPath(`connector-editing-${viewport.label}-synthetic.png`),
      });

      // Cancel must discard the tested draft; reopening reads the saved URL.
      await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
      await expect(dialog).toBeHidden();
      await page.getByRole("button", { name: /^Configure/ }).click();
      await expect(dialog.getByLabel("Wazuh Indexer URL")).toHaveValue(
        "https://indexer.example.com"
      );
      await dialog.getByLabel("Instance name").fill("Updated synthetic Wazuh");
      await dialog.getByLabel("Wazuh Indexer URL").fill("https://updated-indexer.example.com");
      await dialog.getByRole("button", { name: "Save changes" }).click();
      await expect(dialog).toBeHidden();
      await expect(
        page.getByRole("heading", { name: "Updated synthetic Wazuh", exact: true })
      ).toBeVisible();
      expect(api.patches).toEqual([
        {
          name: "Updated synthetic Wazuh",
          connector_config_patch: { indexer_url: "https://updated-indexer.example.com" },
        },
      ]);
      expect(api.unexpected).toEqual([]);
    });
  });
}
