import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SWRConfig } from "swr";
import type { ConnectorCatalogEntry } from "@/lib/api";
import { ConnectorsView } from "./ConnectorsView";

const CONNECTOR_ID = "11111111-1111-4111-8111-111111111111";
const CONNECTOR_PATH = `/api/v1/connectors/${CONNECTOR_ID}`;

function connectorRow() {
  return {
    id: CONNECTOR_ID,
    tenant_id: "22222222-2222-4222-8222-222222222222",
    name: "Production Wazuh",
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
      // Internal runtime state is not a form field and must never be replaced
      // by a stale snapshot sent back from the editor.
      checkpoint: { cursor: "unchanged" },
    } as Record<string, unknown>,
    health_status: "healthy",
    last_health_check: null,
    last_sync: null,
    events_ingested: 42,
    error_count: 0,
    tags: ["production"],
    created_at: "2026-11-01T00:00:00Z",
    updated_at: "2026-11-01T00:00:00Z",
  };
}

const WAZUH_SCHEMA: ConnectorCatalogEntry = {
  connector_id: "wazuh",
  connector_name: "Wazuh",
  category: "siem",
  description: "Wazuh indexer connection",
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

interface RecordedRequest {
  path: string;
  method: string;
  body?: Record<string, unknown>;
}

let requests: RecordedRequest[];
let savedRow: ReturnType<typeof connectorRow>;
let editValues: Record<string, unknown>;
let catalog: ConnectorCatalogEntry[];
let editFailure: { status: number; detail: string } | null;
let saveFailure: { status: number; detail: string } | null;
let testVerdict: { success: boolean; message?: string; error?: string };
let configuredSecretFields: string[];
let saveWait: Promise<void> | null;

function calls(method: string, path = CONNECTOR_PATH) {
  return requests.filter((request) => request.method === method && request.path === path);
}

function renderInventory() {
  render(
    <SWRConfig
      value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}
    >
      <ConnectorsView />
    </SWRConfig>
  );
}

async function openEditor() {
  const user = userEvent.setup();
  renderInventory();
  await screen.findByRole("heading", { name: savedRow.name });
  await user.click(screen.getByRole("button", { name: /^Configure/ }));
  const dialog = await screen.findByRole("dialog", { name: /Edit connector/i });
  await within(dialog).findByLabelText(/^Instance name/i);
  return { user, dialog: within(dialog) };
}

beforeEach(() => {
  requests = [];
  savedRow = connectorRow();
  editValues = {
    indexer_url: savedRow.connector_config.indexer_url,
    // This is a legacy non-secret auth field returned by the safe edit
    // projection, not by the public connector_config response.
    username: "reader",
    index_pattern: savedRow.connector_config.index_pattern,
    min_rule_level: 0,
    verify_tls: false,
    vuln_mode: "inventory",
  };
  catalog = [WAZUH_SCHEMA];
  editFailure = null;
  saveFailure = null;
  testVerdict = { success: true, message: "Connection test passed for draft" };
  configuredSecretFields = ["password"];
  saveWait = null;

  // Keep the real client, response mapping, SWR cache and components. Only
  // the HTTP boundary is replaced; vault/storage behavior is tested by API
  // tests rather than claimed by this browser-side fixture.
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
      const path = String(input);
      const method = options?.method ?? "GET";
      const body = options?.body
        ? (JSON.parse(String(options.body)) as Record<string, unknown>)
        : undefined;
      requests.push({ path, method, body });
      if (method === "GET" && path === "/api/v1/connectors") return Response.json([savedRow]);
      if (method === "GET" && path === "/api/v1/connectors/health") {
        return Response.json({
          total: 1,
          healthy: 1,
          unhealthy: 0,
          unknown: 0,
          drifted: 0,
          drifted_recently: 0,
          last_drift_at: null,
          total_events_ingested: 42,
          total_events_dropped: 0,
        });
      }
      if (method === "GET" && path === "/api/v1/connectors/catalog") {
        return Response.json({ connectors: catalog });
      }
      if (method === "GET" && path === `${CONNECTOR_PATH}/edit_config`) {
        if (editFailure)
          return Response.json({ detail: editFailure.detail }, { status: editFailure.status });
        return Response.json({
          connector: savedRow,
          values: editValues,
          configured_secret_fields: configuredSecretFields,
        });
      }
      if (method === "PATCH" && path === CONNECTOR_PATH) {
        if (saveWait) await saveWait;
        if (saveFailure)
          return Response.json({ detail: saveFailure.detail }, { status: saveFailure.status });
        const {
          auth_config_patch: _credentials,
          connector_config_patch: configPatch,
          ...metadata
        } = body ?? {};
        savedRow = {
          ...savedRow,
          ...metadata,
          connector_config: {
            ...savedRow.connector_config,
            ...(configPatch as Record<string, unknown>),
          },
        };
        return Response.json(savedRow);
      }
      if (method === "POST" && path === `${CONNECTOR_PATH}/test`) {
        return Response.json(testVerdict);
      }
      throw new Error(`Unexpected request: ${method} ${path}`);
    })
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("Connector editing from the inventory", () => {
  it("offers an enabled Configure action for an existing connector", async () => {
    renderInventory();
    await screen.findByRole("heading", { name: "Production Wazuh" });
    expect(screen.getByRole("button", { name: /^Configure/ })).toBeEnabled();
    expect(calls("GET", `${CONNECTOR_PATH}/edit_config`)).toHaveLength(0);
  });

  it("prefills the saved values, including false and zero, without exposing a saved secret", async () => {
    const { dialog } = await openEditor();

    expect(dialog.getByLabelText(/^Instance name/i)).toHaveValue("Production Wazuh");
    expect(dialog.getByLabelText(/^Wazuh Indexer URL/i)).toHaveValue("https://indexer.example.com");
    expect(dialog.getByLabelText(/^Indexer Username/i)).toHaveValue("reader");
    expect(dialog.getByLabelText(/^Minimum Rule Level/i)).toHaveValue(0);
    expect(dialog.getByLabelText(/^Verify TLS Certificate/i)).not.toBeChecked();
    expect(dialog.getByRole("checkbox", { name: "Enabled" })).toBeChecked();
    expect(dialog.getByLabelText(/^Tags/i)).toHaveValue("production");
    const password = dialog.getByLabelText(/^Indexer Password/i);
    expect(password).toHaveAttribute("type", "password");
    expect(password).toHaveValue("");
    expect(password).toHaveAttribute("placeholder", "Leave blank to keep saved value");
    expect(dialog.getByRole("button", { name: "Save changes" })).toBeDisabled();
  });

  it("requires a missing required credential instead of treating every blank secret as saved", async () => {
    configuredSecretFields = [];
    const { user, dialog } = await openEditor();
    expect(dialog.getByLabelText(/^Indexer Password/i)).toBeRequired();
    await user.type(dialog.getByLabelText(/^Instance name/i), " renamed");
    await user.click(dialog.getByRole("button", { name: "Save changes" }));

    expect(calls("PATCH")).toHaveLength(0);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("saves a rename without re-entering credentials and refreshes the inventory", async () => {
    const { user, dialog } = await openEditor();
    await user.clear(dialog.getByLabelText(/^Instance name/i));
    await user.type(dialog.getByLabelText(/^Instance name/i), "Renamed Wazuh");
    await user.click(dialog.getByRole("button", { name: "Save changes" }));

    await screen.findByRole("heading", { name: "Renamed Wazuh" });
    expect(calls("PATCH")).toHaveLength(1);
    const payload = calls("PATCH")[0].body!;
    expect(payload).toMatchObject({ name: "Renamed Wazuh" });
    expect(payload).not.toHaveProperty("auth_config");
    expect(Object.keys(payload.auth_config_patch ?? {})).toEqual([]);
    expect(payload).not.toHaveProperty("connector_config");
    expect(payload.connector_config_patch).toEqual({});
    expect(calls("POST", "/api/v1/connectors")).toHaveLength(0);
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("can rename and disable an OAuth instance without entering application credentials", async () => {
    savedRow = {
      ...savedRow,
      name: "Production Defender",
      connector_type: "azure_defender",
      category: "edr",
      oauth_provisioned: true,
      connector_config: {},
    };
    // The OAuth callback stores tokens in auth_config; a fresh OAuth flow
    // does not populate these manual application fields on the instance.
    editValues = {};
    configuredSecretFields = [];
    catalog = [
      {
        connector_id: "azure_defender",
        connector_name: "Microsoft Defender",
        category: "edr",
        description: "Microsoft 365 Defender unified alerts feed",
        fields: [
          { name: "tenant_id", type: "string", label: "Tenant ID", required: true },
          {
            name: "client_id",
            type: "string",
            label: "Application (Client) ID",
            required: true,
          },
          { name: "client_secret", type: "secret", label: "Client Secret", required: true },
        ],
      },
    ];
    const { user, dialog } = await openEditor();
    expect(dialog.getByLabelText(/^Tenant ID/i)).toHaveValue("");
    expect(dialog.getByLabelText(/^Application \(Client\) ID/i)).toHaveValue("");
    expect(dialog.getByLabelText(/^Client Secret/i)).toHaveValue("");
    await user.clear(dialog.getByLabelText(/^Instance name/i));
    await user.type(dialog.getByLabelText(/^Instance name/i), "Renamed Defender");
    await user.click(dialog.getByRole("checkbox", { name: "Enabled" }));
    await user.click(dialog.getByRole("button", { name: "Save changes" }));

    await screen.findByRole("heading", { name: "Renamed Defender" });
    expect(calls("PATCH")).toHaveLength(1);
    expect(calls("PATCH")[0].body).toEqual({
      name: "Renamed Defender",
      is_enabled: false,
      connector_config_patch: {},
    });
    expect(calls("POST", "/api/v1/connectors")).toHaveLength(0);
  });

  it("sends only the replaced credential and changed non-secret fields as patches", async () => {
    const { user, dialog } = await openEditor();
    await user.type(dialog.getByLabelText(/^Indexer Password/i), "replacement-test-password");
    await user.clear(dialog.getByLabelText(/^Indexer Username/i));
    await user.type(dialog.getByLabelText(/^Indexer Username/i), "new-reader");
    await user.click(dialog.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(calls("PATCH")).toHaveLength(1));
    const payload = calls("PATCH")[0].body!;
    expect(payload.auth_config_patch).toEqual({ password: "replacement-test-password" });
    expect(payload.connector_config_patch).toEqual({ username: "new-reader" });
    expect(payload).not.toHaveProperty("auth_config");
    expect(payload).not.toHaveProperty("connector_config");
  });

  it("preserves explicit false, zero and clearing an optional field in the submitted patch", async () => {
    editValues.verify_tls = true;
    editValues.min_rule_level = 7;
    const { user, dialog } = await openEditor();
    await user.click(dialog.getByLabelText(/^Verify TLS Certificate/i));
    await user.clear(dialog.getByLabelText(/^Minimum Rule Level/i));
    await user.type(dialog.getByLabelText(/^Minimum Rule Level/i), "0");
    await user.clear(dialog.getByLabelText(/^Alert Index Pattern/i));
    await user.click(dialog.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(calls("PATCH")).toHaveLength(1));
    expect(calls("PATCH")[0].body?.connector_config_patch).toEqual({
      verify_tls: false,
      min_rule_level: 0,
      index_pattern: "",
    });
  });

  it("can disable an instance and change its tags without creating a replacement", async () => {
    const { user, dialog } = await openEditor();
    await user.click(dialog.getByRole("checkbox", { name: "Enabled" }));
    await user.clear(dialog.getByLabelText(/^Tags/i));
    await user.type(dialog.getByLabelText(/^Tags/i), "production, critical");
    await user.click(dialog.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(calls("PATCH")).toHaveLength(1));
    expect(calls("PATCH")[0].body).toMatchObject({
      is_enabled: false,
      tags: ["production", "critical"],
    });
    expect(calls("POST", "/api/v1/connectors")).toHaveLength(0);
    expect(calls("DELETE")).toHaveLength(0);
  });

  it("retains the draft and shows the API detail when saving fails, then allows retry", async () => {
    saveFailure = { status: 400, detail: "Destination refused by outbound policy" };
    const { user, dialog } = await openEditor();
    await user.clear(dialog.getByLabelText(/^Instance name/i));
    await user.type(dialog.getByLabelText(/^Instance name/i), "Retry Wazuh");
    await user.click(dialog.getByRole("button", { name: "Save changes" }));

    await dialog.findByText(/Destination refused by outbound policy/);
    expect(dialog.getByLabelText(/^Instance name/i)).toHaveValue("Retry Wazuh");
    expect(screen.getByRole("heading", { name: "Production Wazuh" })).toBeInTheDocument();
    saveFailure = null;
    await user.click(dialog.getByRole("button", { name: "Save changes" }));
    await screen.findByRole("heading", { name: "Retry Wazuh" });
    expect(calls("PATCH")).toHaveLength(2);
  });

  it("cancels without writing and discards typed secrets when reopened", async () => {
    const { user, dialog } = await openEditor();
    await user.type(dialog.getByLabelText(/^Indexer Password/i), "discard-this-test-value");
    await user.click(dialog.getByRole("button", { name: "Cancel" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(calls("PATCH")).toHaveLength(0);
    expect(calls("POST", `${CONNECTOR_PATH}/test`)).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: /^Configure/ }));
    const reopened = within(await screen.findByRole("dialog", { name: /Edit connector/i }));
    expect(await reopened.findByLabelText(/^Indexer Password/i)).toHaveValue("");
  });

  it("keeps keyboard focus inside the editor and returns it to Configure on Escape", async () => {
    const { user, dialog } = await openEditor();
    expect(dialog.getByLabelText(/^Instance name/i)).toHaveFocus();
    await user.tab({ shift: true });
    expect(dialog.getByRole("button", { name: "Close" })).toHaveFocus();
    await user.tab({ shift: true });
    expect(dialog.getByRole("button", { name: "Test connection" })).toHaveFocus();
    await user.tab();
    expect(dialog.getByRole("button", { name: "Close" })).toHaveFocus();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Configure/ })).toHaveFocus();
    expect(calls("PATCH")).toHaveLength(0);
  });

  it("blocks duplicate submits, editing and dismissal while a save is in flight", async () => {
    let finishSave!: () => void;
    saveWait = new Promise<void>((resolve) => {
      finishSave = resolve;
    });
    const { user, dialog } = await openEditor();
    await user.clear(dialog.getByLabelText(/^Instance name/i));
    await user.type(dialog.getByLabelText(/^Instance name/i), "Saved after waiting");
    await user.click(dialog.getByRole("button", { name: "Save changes" }));

    try {
      await waitFor(() => expect(calls("PATCH")).toHaveLength(1));
      expect(dialog.getByLabelText(/^Instance name/i)).toBeDisabled();
      expect(dialog.getByRole("button", { name: "Cancel" })).toBeDisabled();
      expect(dialog.getByRole("button", { name: "Close" })).toBeDisabled();
      expect(dialog.getByRole("button", { name: "Test connection" })).toBeDisabled();
      const savingButton = dialog.getByRole("button", { name: /Saving/ });
      expect(savingButton).toBeDisabled();
      await user.click(savingButton);
      await user.keyboard("{Escape}");
      expect(screen.getByRole("dialog")).toBeInTheDocument();
      expect(calls("PATCH")).toHaveLength(1);
    } finally {
      await act(async () => {
        finishSave();
      });
    }
    await screen.findByRole("heading", { name: "Saved after waiting" });
  });

  it("tests unsaved changes against the existing instance without persisting them", async () => {
    const { user, dialog } = await openEditor();
    await user.clear(dialog.getByLabelText(/^Indexer Username/i));
    await user.type(dialog.getByLabelText(/^Indexer Username/i), "draft-reader");
    await user.click(dialog.getByRole("button", { name: "Test connection" }));

    await dialog.findByText("Connection test passed for draft");
    const tested = calls("POST", `${CONNECTOR_PATH}/test`);
    expect(tested).toHaveLength(1);
    expect(tested[0].body?.connector_config_patch).toEqual({ username: "draft-reader" });
    expect(Object.keys(tested[0].body?.auth_config_patch ?? {})).toEqual([]);
    expect(calls("POST", "/api/v1/connectors/test")).toHaveLength(0);
    expect(calls("PATCH")).toHaveLength(0);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("invalidates a successful test result after the tested settings change", async () => {
    const { user, dialog } = await openEditor();
    await user.click(dialog.getByRole("button", { name: "Test connection" }));
    await dialog.findByText("Connection test passed for draft");
    await user.type(dialog.getByLabelText(/^Indexer Username/i), "-changed");

    expect(dialog.queryByText("Connection test passed for draft")).not.toBeInTheDocument();
    expect(calls("PATCH")).toHaveLength(0);
  });

  it("shows a failed connection test without claiming that the configuration was saved", async () => {
    testVerdict = { success: false, error: "Indexer rejected these credentials" };
    const { user, dialog } = await openEditor();
    await user.type(dialog.getByLabelText(/^Indexer Password/i), "rejected-test-password");
    await user.click(dialog.getByRole("button", { name: "Test connection" }));

    await dialog.findByText(/Indexer rejected these credentials/);
    expect(calls("PATCH")).toHaveLength(0);
    expect(dialog.getByRole("button", { name: "Save changes" })).toBeEnabled();
  });

  it("retries a failed editor read instead of opening an empty editable form", async () => {
    editFailure = { status: 503, detail: "Connector edit configuration unavailable" };
    const user = userEvent.setup();
    renderInventory();
    await screen.findByRole("heading", { name: "Production Wazuh" });
    await user.click(screen.getByRole("button", { name: /^Configure/ }));
    const dialog = within(await screen.findByRole("dialog", { name: /Edit connector/i }));
    await dialog.findByText(/Connector edit configuration unavailable/);
    expect(dialog.queryByLabelText(/^Instance name/i)).not.toBeInTheDocument();
    expect(calls("PATCH")).toHaveLength(0);

    editFailure = null;
    await user.click(dialog.getByRole("button", { name: /Retry/i }));
    expect(await dialog.findByLabelText(/^Instance name/i)).toHaveValue("Production Wazuh");
    expect(calls("GET", `${CONNECTOR_PATH}/edit_config`)).toHaveLength(2);
  });

  it("refuses editing when the saved connector type is absent from the catalog", async () => {
    catalog = [];
    const user = userEvent.setup();
    renderInventory();
    await screen.findByRole("heading", { name: "Production Wazuh" });
    await user.click(screen.getByRole("button", { name: /^Configure/ }));
    const dialog = within(await screen.findByRole("dialog", { name: /Edit connector/i }));

    await dialog.findByText(
      /(?:schema|catalog).*(?:available|found)|(?:available|found).*(?:schema|catalog)/i
    );
    expect(dialog.queryByLabelText(/^Indexer Password/i)).not.toBeInTheDocument();
    expect(calls("PATCH")).toHaveLength(0);
  });
});
