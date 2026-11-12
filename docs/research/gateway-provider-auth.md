# Gateway provider authentication

Research date: 2026-11-12.

## Decision and scope

Keep the existing LiteLLM gateway, task aliases and bundled Ollama defaults.
Use LiteLLM's provider-native authentication instead of setting an OpenAI key
on every alias. Normalize blank optional environment values before the pinned
gateway starts, forward the AWS settings explicitly, and recreate the gateway
when applying configuration changes. No new authentication library, database
migration or provider-routing abstraction is needed.

This decision covers the Compose deployment and its upgrade path. The Helm
chart has its own gateway configuration; it does not consume the Compose
startup wrapper.

| Option | Assessment |
| --- | --- |
| Existing LiteLLM native credentials | Chosen. Already supports provider keys, Bedrock bearer tokens and AWS SDK credentials; preserves the public aliases and local default. |
| Bedrock OpenAI-compatible `custom` BYOK | Conditional alternative for models supporting Chat Completions on the chosen endpoint. Uses an explicit URL/model/Bedrock-key tuple; it does not add IAM signing or make Anthropic compatible. |
| Native Bedrock provider in tenant BYOK | Separate feature. The current provider enum and probe do not implement Bedrock. A complete implementation would need coordinated schema, probe, discovery and runtime-dispatch changes. |
| Replace or upgrade the gateway | Unnecessary for this correction. A newer upstream release fixes empty endpoints, but a version change adds unrelated compatibility risk. Normalize the existing configuration boundary instead. |

## Pinned implementation evidence

`docker-compose.yml` pins `ghcr.io/berriai/litellm:v1.102.1`. The corresponding
source tag resolved to commit `d09bbae1c6df463e425558f60d460437193635da`.
The following are source observations, not claims of successful AWS calls.

| Source and symbol | Observed behavior | Local consequence |
| --- | --- | --- |
| [Bedrock base][R1], `bedrock_bearer_token` | Any non-`None` `api_key`, including an empty string, takes precedence over `AWS_BEARER_TOKEN_BEDROCK`. An empty result selects SigV4. | Remove the generic alias-level `api_key`; an OpenAI key must not mask or replace the Bedrock credential. |
| [Bedrock base][R1], `get_runtime_endpoint` | A non-`None` `api_base` wins, including `""`. | Remove blank `AISOC_LLM_API_BASE` from the process environment before config loading; preserve explicit nonblank endpoints. |
| [Secret resolution][R2], `get_secret` | A missing environment variable resolves to `None`; an explicitly empty value remains empty. | Normalization must happen before LiteLLM resolves the YAML environment references. |
| [Bedrock base][R1], `get_credentials` | Explicit credential/profile selectors test for `None`; blank AWS environment values can select an empty credential or profile. | Remove blank AWS placeholders as well as the blank endpoint. Preserve actual values and the SDK chain. |
| [Bedrock base][R1], `_auth_with_env_vars`, `_auth_with_aws_profile`, `_get_aws_region_name` | Uses Boto3 sessions for ambient/profile credentials and configured-region fallback. | Existing credentials remain usable; host profile files require an explicit container mount. |
| [Converse handler][R3] | Bearer authentication does not resolve a SigV4 principal; the request uses the selected token. | A denied bearer must remain a reported failure, without switching identities. |
| [OpenAI configuration][R4], `get_api_key` | Resolves `OPENAI_API_KEY` when no explicit key is supplied. | Removing the generic alias key preserves native OpenAI authentication. |
| [Production entrypoint][R5] | Runs the gateway CLI, optionally through `ddtrace-run`, using `exec`. | Delegate to the existing entrypoint after normalization to preserve arguments, tracing and signal handling. |

The upstream [empty-endpoint correction][R6] independently identifies the
same distinction between empty and absent values. It is a reference for the
behavior, not code copied into this patch.

## AWS and tenant boundaries

[Boto3's credential chain][R7] supports environment credentials, profiles,
container credentials and instance roles. Docker does not automatically expose
the host's credential files. The optional profile overlay mounts them read-only
only in LiteLLM; an SSO session still needs to be usable, and read-only cache
mounts cannot persist refreshed tokens from inside the container.

[AWS_EC2_METADATA_DISABLED][R8] disables IMDS credential lookup, not environment
or profile credentials. Leave it unset or false when relying on an EC2 role.
The startup wrapper preserves explicit true/false values. [Bedrock API keys][R9]
use `AWS_BEARER_TOKEN_BEDROCK`; they belong upstream of the gateway, separately
from `LITELLM_MASTER_KEY` used by AiSOC clients.

[Model access][R10] is separate from credential discovery. An authorized
administrator can enable a model once; subsequent invocation does not require
every runtime principal to retain Marketplace subscription permissions.
Switching credentials can change the principal and its permissions, and does
not prove that the original role has access.

Tenant BYOK currently applies to Explain and automatic alert triage, not every
workload. To inherit deployment-wide Bedrock, leave that override disabled.
For an independently configured gateway, use the existing LiteLLM-compatible
URL, alias and gateway key as a complete tuple. Blank fields inherit deployment
values in the request-time resolvers. The current custom-provider probe sends
an OpenAI Chat Completions request; entering the raw Bedrock runtime root does
not add native Converse/Invoke support or SigV4 signing. Probe success does
not establish that the actual Explain or triage path uses the same configuration.

AWS separately documents [OpenAI-compatible Chat Completions][R12] on the
runtime endpoint's `/openai/v1` base. For supported models, this makes an
explicit custom URL/model/Bedrock-API-key tuple a protocol-compatible option
without adding a native provider. This is an inference from the documented
API and AiSOC's request construction, not live-account acceptance evidence.
The [API compatibility table][R13] lists Anthropic models as unsupported for
Chat Completions, so their selected native Bedrock route still needs the
gateway. Check each model's endpoint/Region support; runtime model discovery
through `GET /models` is unavailable, so the model ID must be supplied.

## Verification and limits

The regression coverage distinguishes default Ollama, native OpenAI/Anthropic,
Bedrock bearer selection, conflicting keys, blank endpoints, AWS environment
credentials, a mounted profile, IMDSv2 and disabled IMDS. Transport tests start
the pinned gateway and communicate with protocol fixtures over loopback in a
container without network egress. They establish credential selection and wire
behavior, not AWS account/model access, SSO renewal or model quality.

Upgrade coverage includes Make recipe ordering/failure propagation with a
Compose recorder and a separate real Compose test of the mounted configuration
and loaded model. A live deployment must additionally perform completions for
both model tiers; liveness or matching host-file content alone does not prove
which backend answered. Full application end-to-end results and live AWS
verification must be reported separately from these isolated checks.

## Provenance

The inspected LiteLLM files are outside `enterprise/` and covered by the
pinned [MIT license][R11]. This change uses the existing dependency and
references its behavior; it does not vendor upstream implementation code.
The external sources below were inspected on the research date. Runtime test results belong in the verification record for the
actual tested commit.

[R1]: https://github.com/BerriAI/litellm/blob/d09bbae1c6df463e425558f60d460437193635da/litellm/llms/bedrock/base_aws_llm.py
[R2]: https://github.com/BerriAI/litellm/blob/d09bbae1c6df463e425558f60d460437193635da/litellm/secret_managers/main.py
[R3]: https://github.com/BerriAI/litellm/blob/d09bbae1c6df463e425558f60d460437193635da/litellm/llms/bedrock/chat/converse_handler.py
[R4]: https://github.com/BerriAI/litellm/blob/d09bbae1c6df463e425558f60d460437193635da/litellm/llms/openai/chat/gpt_transformation.py
[R5]: https://github.com/BerriAI/litellm/blob/d09bbae1c6df463e425558f60d460437193635da/docker/prod_entrypoint.sh
[R6]: https://github.com/BerriAI/litellm/pull/50449
[R7]: https://docs.aws.amazon.com/boto3/latest/guide/credentials.html
[R8]: https://docs.aws.amazon.com/sdkref/latest/guide/feature-imds-credentials.html
[R9]: https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-use.html
[R10]: https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html
[R11]: https://github.com/BerriAI/litellm/blob/d09bbae1c6df463e425558f60d460437193635da/LICENSE
[R12]: https://docs.aws.amazon.com/bedrock/latest/userguide/inference-chat-completions.html
[R13]: https://docs.aws.amazon.com/bedrock/latest/userguide/models-api-compatibility.html
