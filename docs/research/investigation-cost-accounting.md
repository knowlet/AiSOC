# Investigation cost accounting and prompt caching

Research date: 2026-11-24. Starting revision: `9b9d62190d233303e8a43b7a6a4b701e6334d54b`.

## Decision

Keep the existing gateway and locked client. Book a completed model invocation
once in `safe_ainvoke`; investigator audit entries describe the response without
booking it again. A local response-cache hit places no model call. Retain prompt
cache usage and gateway-reported cache cost components through persistence and
the investigation views, with observation counts distinguishing missing metadata
from a reported zero.

| Existing component | Evidence and decision |
| --- | --- |
| LiteLLM 1.102.1, MIT outside its enterprise directory | Already emits cache-read/write tokens and cost headers. Use those fields; no gateway upgrade or second pricing dependency. |
| LangChain OpenAI 1.8.1, MIT | Normalizes input totals but drops LiteLLM's cache-write spelling and TTL details. Merge the retained raw token usage with normalized metadata. |
| AiSOC fallback price table | Keep explicitly labelled estimates for supported concrete models. Cache pricing requires known rates and a valid token partition; otherwise leave the call unpriced. |

No upstream implementation is copied. This extends the current integration by
reference to its published protocol and pinned source behavior.

## Root causes

`safe_ainvoke` already calls `record_llm_call`. Recon, forensic, responder and
report-writer functions then call it again for the same response, incrementing
both tokens and dollars twice. Their audit entries need the cost description,
not a second write to the active tracker. Wrapper-only paths such as automatic
triage do not have this particular duplication.

The token extractor returns as soon as it sees normalized input/output totals.
It discards all cache details. Its fallback estimator multiplies the entire
prompt by the ordinary input price, including tokens that were read from cache.
Neither the cost table nor the API currently preserves cache usage or cost.

## Pinned upstream contracts

LiteLLM tag `v1.102.1` resolves to
`d09bbae1c6df463e425558f60d460437193635da`. Its
[Anthropic adapter][R1] and [Bedrock Converse adapter][R2] add native cache-read
and cache-write counts to `prompt_tokens`. These counts are subsets of the
normalized total, not extra input to add again.

Its [response-header implementation][R3] emits `x-litellm-response-cost` and
separate cache-read and cache-creation components. The total already includes
those components. `_uncached_input_cost` subtracts cache components from its
internal input cost before exposing the `-input` header. Reasoning is already
part of output cost. Components must never be added to a reported total.

LangChain tag `langchain-openai==1.8.1` resolves to
`6f2bf1c84f07d2517f0aa72368c8b395f0b2c740`. In its [chat model][R4],
`_create_usage_metadata` reads `cached_tokens` but looks for `cache_write_tokens`,
where LiteLLM supplies `cache_creation_tokens`. `_create_chat_result` retains
the raw usage as `response_metadata.token_usage`, including cache-write totals
and TTL details. The implementation must read both representations.

## Pricing boundaries

Gateway-reported money remains separate from list-price estimates. Gateway
figures reflect its configured accounting, not an independently reconciled
provider invoice. Model aliases are not pricing keys, and a provider prefix
must not be stripped to apply another provider's price. Missing cache pricing,
unknown write TTL, invalid usage and unsupported models must not become an
apparently precise full-input-price estimate.

The official [GPT-4o][R5] and [GPT-4o mini][R8] documentation supplies their
ordinary and cached rates. [Anthropic's pricing][R6] distinguishes read, five-minute
write and one-hour write rates; its newer models do not all have the same read
discount. Bedrock calls retain the gateway's platform and region accounting
instead of inheriting direct-provider prices. This change does not
enable provider prompt caching or claim that a repeated prompt guarantees a hit.

## Verification and historical data

Regression coverage must drive the real locked chat client over HTTP through
the investigator call sites, then check persisted totals in PostgreSQL. Fixture
provider responses are labelled synthetic; they establish accounting behavior,
not a paid-provider billing reconciliation. Restore the original production
code in a separate checkout to verify the negative control. Run the existing
agents tests and the deterministic public eval harness before and after.

Historic rows lack the per-call evidence needed to identify every duplicate or
recover missing cache details. Do not divide historical costs by two or
backfill unknown cache usage as measured zero. The additive migration leaves
their observation counts at zero.

[R1]: https://github.com/BerriAI/litellm/blob/d09bbae1c6df463e425558f60d460437193635da/litellm/llms/anthropic/chat/transformation.py
[R2]: https://github.com/BerriAI/litellm/blob/d09bbae1c6df463e425558f60d460437193635da/litellm/llms/bedrock/chat/converse_transformation.py
[R3]: https://github.com/BerriAI/litellm/blob/d09bbae1c6df463e425558f60d460437193635da/litellm/proxy/common_request_processing.py
[R4]: https://github.com/langchain-ai/langchain/blob/6f2bf1c84f07d2517f0aa72368c8b395f0b2c740/libs/partners/openai/langchain_openai/chat_models/base.py
[R5]: https://developers.openai.com/api/docs/models/gpt-4o
[R6]: https://platform.claude.com/docs/en/about-claude/pricing

[R8]: https://developers.openai.com/api/docs/models/gpt-4o-mini
