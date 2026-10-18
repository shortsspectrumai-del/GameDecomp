# Anthropic Claude Native Messages Integration (`v0.3.4+`)

GameDecomp implements the native **Anthropic Messages API** (`/v1/messages`) and **Models API** (`/v1/models`) using Python's standard library—no third-party Anthropic SDK is required. Available models and context window limits are discovered dynamically from your API account rather than hardcoded.

## Studio Configuration

1. Open **Settings → LLM engine** and select **Anthropic · Claude**.
2. Enter your API key in the protected password field, or export `ANTHROPIC_API_KEY` in the server environment before launching Studio.
3. Click **Refresh models** to query the live Models API catalog and select a model ID (or enter a custom model identifier).
4. Return to **Workspace**, import a supported binary, and start the analysis.

API keys are held strictly in memory for the active session and are never persisted to preference files or job checkpoints. Switching providers clears the key field. Binary evidence is transmitted to the selected provider only when an AI reconstruction or translation job is explicitly started; refreshing the model catalog never sends binary data.

For custom gateways or proxies, choose **Custom API**, set the base URL, and select the **Anthropic Messages** protocol.

## CLI Usage

```bash
# Native Anthropic API with interactive key prompt
python3 -m gamedecomp analyze game.so --backend ghidra \
  --llm-provider anthropic --llm-model MODEL_ID --llm-key-prompt \
  --llm-max-output-tokens 4096 -o results-anthropic

# Local or custom gateway speaking Anthropic Messages protocol
python3 -m gamedecomp analyze game.so --backend ghidra \
  --llm-url http://127.0.0.1:8000/v1 --llm-api-format anthropic \
  --llm-model LOCAL_MODEL_ID -o results-local
```

Alternatively, supply `ANTHROPIC_API_KEY` via environment variable. Never pass secret keys inside `--llm-url` or `--llm-model`; both CLI and client preflight checks reject credentials embedded in URLs or model identifiers.

## Reliability, Token Budgeting & Validation Gates

- **Protocol Security:** Top-level `system` prompt separation, explicit `x-api-key` and `anthropic-version` headers, and strict no-redirect policy (`HTTP 3xx` responses are never followed with credentials or source payloads).
- **Dynamic Context Budgeting:** Queries `/v1/models` when available to determine context window and output token ceilings. Enforces stratified evidence budgeting, output token reservation (default `4096` max output tokens, clamped to model limits), and bounded retries.
- **Strict JSON & Stop-Reason Validation:** Rejects duplicate JSON keys, malformed envelopes, `max_tokens` truncations, `model_context_window_exceeded`, `pause_turn`, unexpected `tool_use` stops, and safety `refusal` responses. Records numeric token usage (`input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`) across all attempts.
- **Compiler & Differential Oracle Gate:** All candidate reconstructions must pass evidence citation checks, ABI signature validation, and `gcc`/`clang` object compilation. Candidates are marked `TESTED` only when verified against a finite executable oracle; otherwise compiled candidates remain `UNKNOWN`.

Protocol references: [Anthropic Messages API](https://platform.claude.com/docs/en/api/typescript/messages/create) · [Models API](https://platform.claude.com/docs/en/api/models/list) · [Handling Stop Reasons](https://platform.claude.com/docs/en/build-with-claude/handling-stop-reasons).
