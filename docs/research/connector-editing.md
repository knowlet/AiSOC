# Connector editing

Checked on 2026-11-11 against AiSOC commit
`8a06f2eb51cd9f9386b840061070c92bf18c89f0`.

## Existing contract

`ConnectorInstanceList` disables Configure, while `ConnectorsView` only has
a placeholder handler. `connectorsApi.update` and the tenant-scoped PATCH
endpoint already exist. The creation wizard renders the connector catalog's
fields, so editing should use the same controls and catalog.

The existing PATCH replaces each supplied configuration dictionary. The API
deliberately never returns `auth_config`. Sending the visible form as a
replacement would lose credentials, OAuth refresh state, and configuration
keys maintained by the polling service.

## References and decision

| Source                         | Evidence                                                                                                                                                                                                                                                          | Decision                                                                                                                                                |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| AiSOC, MIT                     | `AddConnectorModal`, `connectorsApi`, `update_connector`, and `test_existing_connector` at the commit above                                                                                                                                                       | Reuse the field renderer, catalog, vault, tenant scoping, and existing saved-instance test route.                                                       |
| SWR 2.5.1, MIT                 | [Mutation implementation](https://github.com/vercel/swr/blob/v2.5.1/src/mutation/index.ts) and [license](https://github.com/vercel/swr/blob/v2.5.1/LICENSE)                                                                                                       | Retain the existing SWR cache ownership in `ConnectorsView`; update the saved row and revalidate the fleet summary after success. No new state library. |
| Data source editor, Apache-2.0 | [ConfigEditor](https://github.com/grafana/grafana-zabbix/blob/c6370ebae29cf571f9b647e4c7745457f8f7a1a1/src/datasource/components/ConfigEditor.tsx) and [license](https://github.com/grafana/grafana-zabbix/blob/c6370ebae29cf571f9b647e4c7745457f8f7a1a1/LICENSE) | Design reference only: separate configured-secret metadata from replacement input. No code copied and no dependency added.                              |

The editor loads a write-authorized, schema-allowlisted projection of saved
non-secret values and configured-secret field names. Secret inputs begin empty.
Only changed public fields and non-empty replacement secrets are submitted.
Additive `auth_config_patch` and `connector_config_patch` fields preserve the
existing replacement API while allowing server-side merges without a stale
client overwriting polling state. An existing-instance test accepts optional
patches, merges them with stored credentials internally, and does not save the
draft or report its verdict as the saved configuration's health.

The connector type stays fixed. Saving a configuration is distinct from testing
vendor connectivity, so operators can save a disabled connector during an
outage. Test results are cleared when the draft changes. The editor has loading,
retry, missing-schema, validation, cancel, and failed-save states.

## Verification scope

Exercise Configure through the real frontend API client, including prefill,
false/zero values, one-secret rotation, no-change secrets, draft-only testing,
failed saves, cancellation, and cache refresh. API tests must cover vault
encryption, legacy auth fields, JSONB merge behavior, cross-tenant refusal,
read-only refusal, SSRF refusal, and the absence of secret values in responses.
Use a negative control against the base tree. Record exact test counts and
runtime in the delivery; a mocked vendor transport does not establish live
vendor connectivity or end-to-end ingestion.
