"use client";

import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { clsx } from "clsx";
import toast from "react-hot-toast";
import {
  connectorsApi,
  type Connector,
  type ConnectorCatalogEntry,
  type ConnectorConfigPatch,
  type ConnectorEditConfig,
  type ConnectorTestResult,
  type UpdateConnectorPayload,
} from "@/lib/api";
import { buildInitialValues, describeApiError, FieldInput } from "./ConnectorFields";

type FormValues = Record<string, string | number | boolean>;

interface LoadedEditor extends ConnectorEditConfig {
  entry: ConnectorCatalogEntry;
  initialValues: FormValues;
}

interface EditConnectorModalProps {
  connectorId: string;
  onClose: () => void;
  onUpdated: (connector: Connector) => void;
}

const inputClass =
  "w-full bg-gray-950/60 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/30";

/** Mounted per editing session so closing also discards replacement secrets. */
export function EditConnectorModal({ connectorId, onClose, onUpdated }: EditConnectorModalProps) {
  const [loaded, setLoaded] = useState<LoadedEditor | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [values, setValues] = useState<FormValues>({});
  const [name, setName] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [tagsText, setTagsText] = useState("");
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<ConnectorTestResult | null>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const nameRef = useRef<HTMLInputElement>(null);
  const feedbackRef = useRef<HTMLDivElement>(null);
  const busy = saving || testing;

  useEffect(() => {
    let cancelled = false;
    // The parent keys each editing session by connectorId. Retry resets its
    // error in the click handler, so loading never copies state in an effect.
    Promise.all([connectorsApi.editConfig(connectorId), connectorsApi.catalog()])
      .then(([editor, catalog]) => {
        if (cancelled) return;
        const entry = catalog.connectors.find(
          (item) => item.connector_id === editor.connector.type
        );
        if (!entry)
          throw new Error(`The configuration schema for ${editor.connector.type} is unavailable.`);
        const initialValues = buildInitialValues(entry.fields);
        for (const field of entry.fields) {
          if (field.type === "secret") continue;
          const value = editor.values[field.name];
          if (
            typeof value === "string" ||
            typeof value === "number" ||
            typeof value === "boolean"
          ) {
            initialValues[field.name] = value;
          }
        }
        setLoaded({ ...editor, entry, initialValues });
        setValues(initialValues);
        setName(editor.connector.name);
        setEnabled(editor.connector.enabled ?? false);
        setTagsText((editor.connector.tags ?? []).join(", "));
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setLoadError(describeApiError(err, "Failed to load connector configuration"));
      });
    return () => {
      cancelled = true;
    };
  }, [connectorId, attempt]);

  useEffect(() => {
    const previousFocus =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    dialogRef.current?.focus();
    return () => {
      document.body.style.overflow = previousOverflow;
      previousFocus?.focus();
    };
  }, []);

  useEffect(() => {
    if (loaded) nameRef.current?.focus();
  }, [loaded]);

  useEffect(() => {
    if (saveError || testResult) feedbackRef.current?.scrollIntoView?.({ block: "nearest" });
  }, [saveError, testResult]);

  const clearFeedback = () => {
    setSaveError(null);
    setTestResult(null);
  };

  const configPatch: ConnectorConfigPatch = {};
  if (loaded) {
    const auth: Record<string, unknown> = {};
    const config: Record<string, unknown> = {};
    for (const field of loaded.entry.fields) {
      const value = values[field.name];
      if (field.type === "secret") {
        if (value !== "" && value !== undefined) auth[field.name] = value;
      } else if (value !== loaded.initialValues[field.name]) {
        config[field.name] = value;
      }
    }
    if (Object.keys(auth).length) configPatch.auth_config_patch = auth;
    if (Object.keys(config).length) configPatch.connector_config_patch = config;
  }

  const update: UpdateConnectorPayload = { ...configPatch };
  if (loaded) {
    if (name.trim() !== loaded.connector.name) update.name = name.trim();
    if (enabled !== loaded.connector.enabled) update.is_enabled = enabled;
    const tags = [
      ...new Set(
        tagsText
          .split(",")
          .map((tag) => tag.trim())
          .filter(Boolean)
      ),
    ];
    if (JSON.stringify(tags) !== JSON.stringify(loaded.connector.tags ?? [])) update.tags = tags;
  }
  const dirty = Object.keys(update).length > 0;

  const validate = () => {
    if (!formRef.current?.reportValidity()) return false;
    if (!name.trim()) {
      setSaveError("Please give this connector an instance name");
      nameRef.current?.focus();
      return false;
    }
    return true;
  };

  const handleSave = async (event: FormEvent) => {
    event.preventDefault();
    if (!loaded || busy || !dirty || !validate()) return;
    setSaving(true);
    setSaveError(null);
    try {
      const connector = await connectorsApi.update(connectorId, {
        ...update,
        connector_config_patch: update.connector_config_patch ?? {},
      });
      setValues({});
      toast.success(`Updated ${connector.name}`);
      onUpdated(connector);
      onClose();
    } catch (err) {
      setSaveError(describeApiError(err, "Failed to save connector"));
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    if (!loaded || busy || !validate()) return;
    setTesting(true);
    setSaveError(null);
    setTestResult(null);
    try {
      // Even an empty body means "test this draft", without changing saved health.
      setTestResult(await connectorsApi.test(connectorId, configPatch));
    } catch (err) {
      setTestResult({ success: false, error: describeApiError(err, "Test request failed") });
    } finally {
      setTesting(false);
    }
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.stopPropagation();
      if (!busy) onClose();
    }
    if (event.key !== "Tab") return;
    const focusable = dialogRef.current?.querySelectorAll<HTMLElement>(
      "button:enabled, input:enabled, select:enabled, textarea:enabled, a[href]"
    );
    if (!focusable?.length) {
      event.preventDefault();
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (
      event.shiftKey &&
      (document.activeElement === first || document.activeElement === dialogRef.current)
    ) {
      event.preventDefault();
      last.focus();
    } else if (
      !event.shiftKey &&
      (document.activeElement === last || document.activeElement === dialogRef.current)
    ) {
      event.preventDefault();
      first.focus();
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="edit-connector-title"
        aria-describedby="edit-connector-description"
        tabIndex={-1}
        onKeyDown={handleKeyDown}
        className="w-full max-w-2xl max-h-[90vh] flex flex-col bg-gray-950 border border-gray-800 rounded-xl shadow-2xl outline-none"
      >
        <div className="shrink-0 flex items-start justify-between gap-4 px-6 py-4 border-b border-gray-800">
          <div className="min-w-0 flex-1">
            <h2 id="edit-connector-title" className="text-base font-semibold text-gray-100">
              Edit connector
            </h2>
            <p
              id="edit-connector-description"
              className="text-xs text-gray-400 mt-1 break-words line-clamp-2"
            >
              {loaded
                ? `${loaded.entry.connector_name} · ${loaded.connector.name}`
                : "Load saved settings to edit this connector."}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={busy}
            aria-label="Close"
            className="shrink-0 text-gray-400 hover:text-gray-200 disabled:opacity-50 px-2 py-1"
          >
            ✕
          </button>
        </div>

        {!loaded ? (
          <div className="p-6 space-y-4">
            {loadError ? (
              <>
                <p role="alert" className="text-sm text-red-300">
                  Failed to load connector configuration: {loadError}
                </p>
                <button
                  type="button"
                  onClick={() => {
                    setLoadError(null);
                    setAttempt((n) => n + 1);
                  }}
                  className="text-sm text-blue-400 hover:text-blue-300"
                >
                  Retry
                </button>
              </>
            ) : (
              <p role="status" className="text-sm text-gray-400">
                Loading connector configuration…
              </p>
            )}
            <button
              type="button"
              onClick={onClose}
              className="block text-sm text-gray-400 hover:text-gray-200"
            >
              Cancel
            </button>
          </div>
        ) : (
          <form ref={formRef} onSubmit={handleSave} className="flex flex-col min-h-0">
            <div className="min-h-0 overflow-y-auto px-6 py-5 space-y-5">
              <fieldset disabled={busy} className="space-y-5 disabled:opacity-70">
                <div>
                  <label
                    htmlFor="edit-connector-name"
                    className="block text-xs font-semibold text-gray-300 mb-1"
                  >
                    Instance name
                  </label>
                  <input
                    ref={nameRef}
                    id="edit-connector-name"
                    value={name}
                    maxLength={255}
                    required
                    className={inputClass}
                    onChange={(e) => {
                      setName(e.target.value);
                      clearFeedback();
                    }}
                  />
                </div>
                <label className="flex items-center gap-2 text-sm text-gray-300">
                  <input
                    type="checkbox"
                    checked={enabled}
                    onChange={(e) => {
                      setEnabled(e.target.checked);
                      clearFeedback();
                    }}
                    className="h-4 w-4 accent-blue-500"
                  />
                  Enabled
                </label>
                <div>
                  <label
                    htmlFor="edit-connector-tags"
                    className="block text-xs font-semibold text-gray-300 mb-1"
                  >
                    Tags
                  </label>
                  <input
                    id="edit-connector-tags"
                    value={tagsText}
                    onChange={(e) => {
                      setTagsText(e.target.value);
                      clearFeedback();
                    }}
                    className={inputClass}
                    aria-describedby="edit-connector-tags-help"
                  />
                  <p id="edit-connector-tags-help" className="mt-1 text-xs text-gray-500">
                    Separate tags with commas.
                  </p>
                </div>
                <div className="border-t border-gray-800 pt-4">
                  <h3 className="text-sm font-medium text-gray-200">Connection settings</h3>
                  <p className="mt-1 text-xs text-gray-400">
                    Leave saved credentials blank to keep their current values. Enter a new value
                    only to replace it.
                  </p>
                  {loaded.connector.oauthProvisioned && (
                    <p className="mt-1 text-xs text-gray-400">
                      This connector uses OAuth. Its saved authorization is preserved.
                    </p>
                  )}
                </div>
                {loaded.entry.fields.map((field) => {
                  const savedSecret =
                    field.type === "secret" && loaded.configuredSecretFields.includes(field.name);
                  const keepSecret =
                    field.type === "secret" && (savedSecret || loaded.connector.oauthProvisioned);
                  // OAuth callbacks can store tokens without the manual sign-in
                  // fields. Preserve those absent values until explicitly edited.
                  const keepOAuthSetting =
                    loaded.connector.oauthProvisioned &&
                    !Object.prototype.hasOwnProperty.call(loaded.values, field.name) &&
                    values[field.name] === loaded.initialValues[field.name];
                  const editableField = keepSecret
                    ? { ...field, required: false, placeholder: "Leave blank to keep saved value" }
                    : keepOAuthSetting
                      ? { ...field, required: false }
                      : field;
                  const id = `edit-connector-field-${field.name}`;
                  return (
                    <div key={field.name}>
                      <label
                        htmlFor={id}
                        className="block text-xs font-semibold text-gray-300 mb-1"
                      >
                        {field.label}
                        {editableField.required && (
                          <span className="text-red-400 ml-1" aria-hidden="true">
                            *
                          </span>
                        )}
                      </label>
                      <FieldInput
                        id={id}
                        describedBy={field.help_text || savedSecret ? `${id}-help` : undefined}
                        field={editableField}
                        value={values[field.name]}
                        onChange={(value) => {
                          setValues((previous) => ({ ...previous, [field.name]: value }));
                          clearFeedback();
                        }}
                      />
                      {(field.help_text || savedSecret) && (
                        <p id={`${id}-help`} className="mt-1 text-xs text-gray-500">
                          {savedSecret ? "A value is stored securely. " : ""}
                          {field.help_text}
                        </p>
                      )}
                    </div>
                  );
                })}
              </fieldset>
              <div ref={feedbackRef} className="space-y-3 break-words">
                {saveError && (
                  <p role="alert" className="text-sm text-red-300">
                    {saveError}
                  </p>
                )}
                {testResult && (
                  <p
                    role={testResult.success ? "status" : "alert"}
                    className={clsx(
                      "text-sm",
                      testResult.success ? "text-green-300" : "text-red-300"
                    )}
                  >
                    {testResult.success
                      ? (testResult.message ?? "Connection test passed")
                      : (testResult.error ?? testResult.message ?? "Connection test failed")}
                  </p>
                )}
              </div>
            </div>
            <div className="shrink-0 border-t border-gray-800 px-6 py-4 space-y-3">
              <p className="text-xs text-gray-500">
                Testing does not save changes. Saved settings take effect on the next connector
                reload.
              </p>
              <div className="flex flex-wrap justify-between gap-2">
                <button
                  type="button"
                  onClick={onClose}
                  disabled={busy}
                  className="text-sm text-gray-400 hover:text-gray-200 px-3 py-2 disabled:opacity-50"
                >
                  Cancel
                </button>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={handleTest}
                    disabled={busy}
                    className="text-sm bg-gray-800 hover:bg-gray-700 text-gray-200 px-3 py-2 rounded-lg disabled:opacity-50"
                  >
                    {testing ? "Testing…" : "Test connection"}
                  </button>
                  <button
                    type="submit"
                    disabled={busy || !dirty}
                    className="text-sm bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg disabled:opacity-50"
                  >
                    {saving ? "Saving…" : "Save changes"}
                  </button>
                </div>
              </div>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
