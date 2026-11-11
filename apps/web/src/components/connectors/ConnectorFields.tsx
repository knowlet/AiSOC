"use client";

import { clsx } from "clsx";
import { ApiError, type ConnectorSchemaField } from "@/lib/api";

// ─── Field rendering helpers ────────────────────────────────────────────────

/**
 * Compute the initial form values for a catalog entry.
 *
 * Defaults from the schema flow into ``connector_config`` so the operator
 * sees them already populated. Secrets always start empty — never seed a
 * default secret, even if the schema were to declare one.
 *
 * A required select with no default starts on its first option: it renders
 * no blank placeholder, so the browser already shows that option as chosen,
 * and the state has to match what the operator sees.
 */
export function buildInitialValues(
  fields: ConnectorSchemaField[]
): Record<string, string | number | boolean> {
  const values: Record<string, string | number | boolean> = {};
  for (const f of fields) {
    if (f.type === "secret") {
      values[f.name] = "";
      continue;
    }
    if (f.default !== undefined && f.default !== null) {
      values[f.name] = f.default as string | number | boolean;
      continue;
    }
    if (f.type === "boolean") {
      values[f.name] = false;
      continue;
    }
    if (f.type === "number") {
      values[f.name] = 0;
      continue;
    }
    const firstOption = f.options?.[0];
    if (f.type === "select" && f.required && firstOption) {
      values[f.name] = firstOption.value;
      continue;
    }
    values[f.name] = "";
  }
  return values;
}

/**
 * Split a flat values dict into ``auth_config`` (secrets) and
 * ``connector_config`` (everything else).
 *
 * The backend expects this split because secrets get encrypted and
 * non-secrets stay plaintext for poll-config readability in the UI.
 */
export function partitionFormValues(
  fields: ConnectorSchemaField[],
  values: Record<string, string | number | boolean>
): { auth_config: Record<string, unknown>; connector_config: Record<string, unknown> } {
  const auth_config: Record<string, unknown> = {};
  const connector_config: Record<string, unknown> = {};
  for (const f of fields) {
    const v = values[f.name];
    // Empty optional fields are omitted entirely so the backend doesn't
    // need to disambiguate between "operator typed empty string" and
    // "operator did not provide".
    const isEmpty = v === "" || v === null || v === undefined;
    if (isEmpty && !f.required) continue;
    if (f.type === "secret") {
      auth_config[f.name] = v;
    } else {
      connector_config[f.name] = v;
    }
  }
  return { auth_config, connector_config };
}

interface FieldInputProps {
  id?: string;
  describedBy?: string;
  field: ConnectorSchemaField;
  value: string | number | boolean;
  onChange: (next: string | number | boolean) => void;
}

export function FieldInput({ field, value, onChange, id, describedBy }: FieldInputProps) {
  const baseClass =
    "w-full bg-gray-950/60 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/30 transition-colors";

  switch (field.type) {
    case "secret":
      return (
        <input
          id={id}
          aria-describedby={describedBy}
          type="password"
          autoComplete="new-password"
          value={String(value ?? "")}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder ?? "••••••••"}
          className={clsx(baseClass, "font-mono")}
          required={field.required}
        />
      );
    case "textarea":
      return (
        <textarea
          id={id}
          aria-describedby={describedBy}
          value={String(value ?? "")}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          rows={6}
          className={clsx(baseClass, "font-mono text-xs resize-y min-h-[120px]")}
          required={field.required}
        />
      );
    case "select":
      return (
        <select
          id={id}
          aria-describedby={describedBy}
          value={String(value ?? "")}
          onChange={(e) => onChange(e.target.value)}
          className={baseClass}
          required={field.required}
        >
          {!field.required && <option value="">— none —</option>}
          {(field.options ?? []).map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      );
    case "boolean":
      return (
        <label className="flex items-center gap-2 cursor-pointer select-none">
          <input
            id={id}
            aria-describedby={describedBy}
            type="checkbox"
            checked={Boolean(value)}
            onChange={(e) => onChange(e.target.checked)}
            className="h-4 w-4 rounded border-gray-700 bg-gray-900 text-blue-500 focus:ring-blue-500/30"
          />
          <span className="text-sm text-gray-300">{field.placeholder ?? "Enabled"}</span>
        </label>
      );
    case "number":
      return (
        <input
          id={id}
          aria-describedby={describedBy}
          type="number"
          value={typeof value === "number" ? value : String(value ?? "")}
          onChange={(e) => {
            onChange(e.target.value === "" ? "" : Number(e.target.value));
          }}
          placeholder={field.placeholder}
          className={baseClass}
          required={field.required}
        />
      );
    case "string":
    default:
      return (
        <input
          id={id}
          aria-describedby={describedBy}
          type="text"
          value={String(value ?? "")}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          className={baseClass}
          required={field.required}
        />
      );
  }
}

/**
 * Turn a thrown request error into something an operator can act on.
 *
 * `ApiError.message` is the status line — `API 502 Bad Gateway — /api/v1/…`.
 * Everything that identifies the fault lives in `body`, which FastAPI sends as
 * `{"detail": "…"}`. This matters most for the failure that is not the
 * customer's: when the API cannot authenticate to AiSOC's own connectors
 * service, the detail names the status, the service and the variable to set,
 * and the status line alone names none of them.
 */
export function describeApiError(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.body) {
      try {
        const parsed = JSON.parse(err.body) as { detail?: unknown };
        if (typeof parsed.detail === "string" && parsed.detail.trim()) {
          return parsed.detail;
        }
      } catch {
        // Not JSON — a proxy error page or a truncated body. Fall through to
        // the status line, which at least names the status.
      }
    }
    return err.message;
  }
  return err instanceof Error ? err.message : fallback;
}
