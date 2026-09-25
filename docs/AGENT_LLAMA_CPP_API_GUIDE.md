# llama.cpp API Provider — Agent Usage Guide

> **Purpose:** This file tells an AI/coding agent exactly how to use this self-hosted llama.cpp OpenAI-compatible API safely and efficiently.

## 0. TL;DR for agents

This is a **llama.cpp `llama-server` OpenAI-compatible provider**.

Use these environment variables:

```bash
LLM_URL="https://...or-http://host:port"
LLM_API_KEY="..."
```

The OpenAI-compatible base is normally:

```text
$LLM_URL/v1
```

Current model alias used in examples:

```text
qwen38
```

### Default rule

For normal chat, coding, extraction, summarization, routing, and tool-style work:

```json
"reasoning_effort": "none"
```

Use reasoning only when the task genuinely benefits from it.

### Minimal request

```bash
curl "$LLM_URL/v1/chat/completions" \
  -H "Authorization: Bearer $LLM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen38",
    "messages": [
      {"role": "user", "content": "Hello. Reply briefly."}
    ],
    "reasoning_effort": "none",
    "max_tokens": 256
  }'
```

The visible answer is:

```text
choices[0].message.content
```

If reasoning is enabled, llama.cpp may additionally return:

```text
choices[0].message.reasoning_content
```

---

# 1. Provider contract

Treat this provider like an OpenAI-compatible Chat Completions server.

Primary endpoint:

```text
POST /v1/chat/completions
```

Useful endpoints to probe:

```text
GET /v1/models
```

Depending on the llama.cpp build/configuration, additional endpoints may exist. Do not assume unsupported OpenAI APIs without checking the server.

Authentication:

```http
Authorization: Bearer <API_KEY>
```

Content type:

```http
Content-Type: application/json
```

---

# 2. Normal chat request

Use this for most tasks.

```json
{
  "model": "qwen38",
  "messages": [
    {
      "role": "system",
      "content": "You are a concise technical assistant."
    },
    {
      "role": "user",
      "content": "Explain TCP slow start briefly."
    }
  ],
  "reasoning_effort": "none",
  "temperature": 0.7,
  "max_tokens": 512
}
```

## Why `reasoning_effort: "none"` is the default

On this server, reasoning-capable models may otherwise spend a large portion of the completion budget inside `reasoning_content`.

For simple tasks this can:
- increase latency,
- consume unnecessary completion tokens,
- sometimes reach `max_tokens` before producing enough visible content.

We experimentally confirmed that:

```json
"reasoning_effort": "none"
```

cleanly disables reasoning for the currently served model and returns the answer directly in `message.content`.

---

# 3. Reasoning modes

## Fast/default mode

Use for:
- ordinary Q&A,
- coding boilerplate,
- rewriting,
- extraction,
- classification,
- summaries,
- straightforward algorithms,
- API/tool orchestration.

```json
"reasoning_effort": "none"
```

## Bounded reasoning

For harder problems, the current llama.cpp server supports a reasoning token budget:

```json
"reasoning_budget_tokens": 256
```

Example:

```bash
curl "$LLM_URL/v1/chat/completions" \
  -H "Authorization: Bearer $LLM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen38",
    "messages": [
      {
        "role": "user",
        "content": "Analyze this algorithm and find the subtle bug."
      }
    ],
    "reasoning_budget_tokens": 256,
    "max_tokens": 1024
  }'
```

Possible heuristic:

```text
Simple task                 reasoning_effort = none
Moderate reasoning          reasoning_budget_tokens = 128–256
Hard reasoning              reasoning_budget_tokens = 512–1024
Deep/experimental reasoning unrestricted/default
```

Do **not** use `/no_think` as a prompt prefix for this provider. It was tested and the currently served model/template ignored it.

---

# 4. Important token-budget behavior

`max_tokens` limits total generated completion tokens.

When reasoning is enabled, generated reasoning can consume part of that budget.

Therefore:

```json
{
  "reasoning_budget_tokens": 256,
  "max_tokens": 256
}
```

is usually a bad combination because reasoning may consume most of the generation budget.

Prefer something like:

```json
{
  "reasoning_budget_tokens": 256,
  "max_tokens": 1024
}
```

for a reasoning task.

For non-reasoning requests:

```json
{
  "reasoning_effort": "none",
  "max_tokens": 256
}
```

is perfectly reasonable for short answers.

---

# 5. Python — OpenAI SDK

Because llama.cpp exposes an OpenAI-compatible endpoint, use the normal OpenAI client with a custom `base_url`.

```python
import os
from openai import OpenAI

client = OpenAI(
    base_url=os.environ["LLM_URL"].rstrip("/") + "/v1",
    api_key=os.environ["LLM_API_KEY"],
)

response = client.chat.completions.create(
    model="qwen38",
    messages=[
        {"role": "system", "content": "Answer concisely."},
        {"role": "user", "content": "Explain Dijkstra's algorithm."},
    ],
    max_tokens=512,
    extra_body={"reasoning_effort": "none"},
)

print(response.choices[0].message.content)
```

For llama.cpp-specific parameters not exposed directly by the SDK, place them in:

```python
extra_body = {...}
```

For example:

```python
extra_body = {"reasoning_budget_tokens": 256}
```

---

# 6. Python — raw HTTP

```python
import os
import requests

url = os.environ["LLM_URL"].rstrip("/") + "/v1/chat/completions"

payload = {
    "model": "qwen38",
    "messages": [{"role": "user", "content": "Write a Java binary search."}],
    "reasoning_effort": "none",
    "max_tokens": 512,
}

r = requests.post(
    url,
    headers={
        "Authorization": f"Bearer {os.environ['LLM_API_KEY']}",
        "Content-Type": "application/json",
    },
    json=payload,
    timeout=180,
)

r.raise_for_status()
data = r.json()

print(data["choices"][0]["message"]["content"])
```

---

# 7. JavaScript / Node.js

```javascript
const base = process.env.LLM_URL.replace(/\/$/, "");
const key = process.env.LLM_API_KEY;

const response = await fetch(`${base}/v1/chat/completions`, {
  method: "POST",
  headers: {
    "Authorization": `Bearer ${key}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    model: "qwen38",
    messages: [
      { role: "user", content: "Explain REST vs RPC briefly." }
    ],
    reasoning_effort: "none",
    max_tokens: 512,
  }),
});

if (!response.ok) {
  throw new Error(`LLM request failed: ${response.status} ${await response.text()}`);
}

const data = await response.json();
console.log(data.choices[0].message.content);
```

---

# 8. Streaming

If the server/client build supports standard OpenAI-compatible SSE streaming, request:

```json
"stream": true
```

Example shape:

```bash
curl -N "$LLM_URL/v1/chat/completions" \
  -H "Authorization: Bearer $LLM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen38",
    "messages": [
      {"role": "user", "content": "Explain transformers in 5 bullets."}
    ],
    "reasoning_effort": "none",
    "max_tokens": 512,
    "stream": true
  }'
```

An agent should parse the SSE chunks instead of waiting for a single final JSON object.

---

# 9. Response shape

Typical response:

```json
{
  "choices": [
    {
      "finish_reason": "stop",
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "..."
      }
    }
  ],
  "model": "qwen38",
  "usage": {
    "prompt_tokens": 33,
    "completion_tokens": 132,
    "total_tokens": 165
  }
}
```

Reasoning mode may return:

```json
{
  "message": {
    "role": "assistant",
    "content": "...",
    "reasoning_content": "..."
  }
}
```

Do not display `reasoning_content` to end users unless the application explicitly wants it.

llama.cpp may also return non-standard performance fields such as:

```json
"timings": {
  "prompt_ms": 268.367,
  "predicted_ms": 4075.437,
  "predicted_per_second": 32.1
}
```

These are useful for diagnostics and benchmarking.

---

# 10. Finish reasons

Always inspect:

```text
choices[0].finish_reason
```

Common values include:

```text
stop
length
```

`length` means the generation hit its configured token limit.

If useful content is truncated, increase `max_tokens`.

Do not blindly retry every `length` response: sometimes the caller intentionally requested a strict limit.

---

# 11. Concurrency

The server is configured/designed to handle approximately **4 concurrent requests**.

Do not create four separate llama-server processes to achieve this.

Send normal concurrent HTTP requests to the same endpoint.

Example shell test:

```bash
seq 1 4 | xargs -I{} -P 4 bash -c '
curl -s "$LLM_URL/v1/chat/completions" \
  -H "Authorization: Bearer $LLM_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"model\":\"qwen38\",
    \"messages\":[
      {
        \"role\":\"user\",
        \"content\":\"Request {}: explain mutexes briefly.\"
      }
    ],
    \"reasoning_effort\":\"none\",
    \"max_tokens\":256
  }"
'
```

Observed behavior after concurrency tuning:
- one request: roughly ~32 generated tokens/sec,
- four concurrent requests: roughly ~21–23 generated tokens/sec **per request** in the tested workload,
- all four requests make progress concurrently.

Exact numbers vary by model, prompt, context, GPU state, quantization, and batch settings.

---

# 12. Retry policy

This provider runs inside a constrained Jupyter/container environment.

Possible transient errors include:

```text
500 Resource temporarily unavailable
```

Do not hammer the API with immediate infinite retries.

Recommended application policy:

```text
attempt 1
↓ failure
wait ~0.5–1 s
attempt 2
↓ failure
wait ~2 s
attempt 3
↓
fail visibly
```

Use capped exponential backoff plus jitter.

Suggested retryable cases:
- HTTP 429
- HTTP 500 when clearly transient
- HTTP 502
- HTTP 503
- connection reset/timeout

Do not retry malformed requests or authentication failures.

---

# 13. Server resource constraint agents MUST know

This Jupyter container exposes approximately:

```text
100 logical CPUs
```

but has a cgroup task/thread limit of:

```text
pids.max = 512
```

Linux cgroup task accounting includes threads.

Therefore a program seeing 100 CPUs must **not** automatically create 100+ worker threads per process.

The environment has intentionally bounded thread pools:

```bash
TOKIO_WORKER_THREADS=4
OMP_NUM_THREADS=4
MKL_NUM_THREADS=4
OPENBLAS_NUM_THREADS=4
NUMEXPR_NUM_THREADS=4
```

Do not reset these to `100`.

Do not launch duplicate llama-server processes unless explicitly requested.

When debugging:

```bash
cat /sys/fs/cgroup/pids.current
cat /sys/fs/cgroup/pids.max

ps -eo pid,ppid,comm,nlwp,%cpu,%mem --sort=-nlwp | head -20

pgrep -af llama
```

Target substantial headroom below the 512-task ceiling.

---

# 14. Health/debug commands

## Check server

```bash
curl -s \
  -H "Authorization: Bearer $LLM_API_KEY" \
  "$LLM_URL/v1/models"
```

## Quick generation

```bash
curl -s "$LLM_URL/v1/chat/completions" \
  -H "Authorization: Bearer $LLM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model":"qwen38",
    "messages":[{"role":"user","content":"Reply with OK."}],
    "reasoning_effort":"none",
    "max_tokens":32
  }'
```

## Check GPU

```bash
nvidia-smi
```

## Check llama processes and threads

```bash
ps -eo pid,ppid,comm,nlwp,%cpu,%mem,args \
  | grep -E '[l]lama'
```

## Check task budget

```bash
printf "tasks: "
cat /sys/fs/cgroup/pids.current
printf "limit: "
cat /sys/fs/cgroup/pids.max
```

---

# 15. Agent behavioral rules for this provider

When an agent is given access to this API:

1. **Prefer `reasoning_effort: "none"` by default.**
2. Enable reasoning only when the task actually needs it.
3. Do not use `/no_think`; it was ineffective with the current template.
4. Set a finite `max_tokens`.
5. Parse `choices[0].message.content`.
6. Check `finish_reason`.
7. Treat `reasoning_content` as optional/internal metadata.
8. Reuse the single server; do not spawn one server per request.
9. Concurrency up to roughly four requests is expected.
10. Use retries with backoff for transient server failures.
11. Never assume `nproc=100` means 100 threads are safe.
12. Never change the global thread limits without measuring cgroup task usage.
13. Do not expose the API key in logs, commits, prompts, or client-side browser code.
14. Prefer server-side calls when the API key must remain secret.
15. Benchmark changes using both single-request and 4-request tests.

---

# 16. Recommended request presets

## FAST

```json
{
  "reasoning_effort": "none",
  "temperature": 0.7,
  "max_tokens": 512
}
```

Use for almost everything.

## REASON

```json
{
  "reasoning_budget_tokens": 256,
  "temperature": 0.7,
  "max_tokens": 1024
}
```

## DEEP

```json
{
  "reasoning_budget_tokens": 1024,
  "temperature": 0.7,
  "max_tokens": 2048
}
```

Use DEEP sparingly because it directly increases latency and completion cost.

---

# 17. Candidate model upgrades for the A100 40 GB

The server currently has enough GPU headroom to test larger/higher-quality GGUFs.

## Candidate A — Qwen3.6-35B-A3B

Official ggml-org GGUF:

```text
ggml-org/Qwen3.6-35B-A3B-GGUF
```

Current published sizes include approximately:

```text
Q4_K_M   20.4 GB
Q8_0     36.9 GB
```

A 36.9 GB Q8 model leaves too little room on a 40 GB A100 for comfortable KV cache, context, CUDA overhead, and four parallel slots.

Recommended experiment:

```text
Q5/Q6-class quant if available -> likely best quality/VRAM compromise
Q4_K_M                         -> safest/high-concurrency baseline
Q8_0                           -> quality experiment only with small context/concurrency
```

Example baseline:

```bash
llama-server \
  -hf ggml-org/Qwen3.6-35B-A3B-GGUF:Q4_K_M \
  <existing server flags>
```

Do not replace the current model blindly. Benchmark it first.

---

## Candidate B — GLM-4.7-Flash

Official ggml-org GGUF:

```text
ggml-org/GLM-4.7-Flash-GGUF
```

Published model size:

```text
30B parameters
```

Published GGUF size:

```text
Q8_0 ≈ 31.8 GB
```

This is interesting on a 40 GB A100 because Q8 leaves materially more room than Qwen3.6-35B-A3B Q8 for KV cache and runtime overhead.

Example:

```bash
llama-server \
  -hf ggml-org/GLM-4.7-Flash-GGUF:Q8_0 \
  <existing server flags>
```

This is worth benchmarking as a high-quality 8-bit alternative.

---

# 18. Model-selection rule

Do not choose a model based only on "VRAM used".

For this provider, optimize the whole system:

```text
quality
+ single-request tok/s
+ 4-request aggregate throughput
+ time to first token
+ usable context per slot
+ KV-cache VRAM
+ reliability
+ reasoning behavior
+ tool/coding quality
```

A model using 39.5/40 GB may be worse operationally than one using 28–32 GB if the latter leaves enough memory for:
- four parallel contexts,
- KV cache,
- CUDA buffers,
- longer prompts,
- stable operation.

Suggested benchmark matrix:

```text
Current model
Qwen3.6-35B-A3B Q4_K_M
Qwen3.6-35B-A3B Q5/Q6 if available
GLM-4.7-Flash Q8_0
```

For each, measure:

```text
VRAM idle
VRAM with 1 request
VRAM with 4 requests
prompt tok/s
generation tok/s
aggregate tok/s
TTFT
4-request p50/p95 completion latency
quality on a fixed prompt suite
```

---

# 19. Source references for maintainers

llama.cpp server:
https://github.com/ggml-org/llama.cpp/tree/master/tools/server

Qwen3.6-35B-A3B GGUF:
https://huggingface.co/ggml-org/Qwen3.6-35B-A3B-GGUF

GLM-4.7-Flash GGUF:
https://huggingface.co/ggml-org/GLM-4.7-Flash-GGUF

---

# 20. One-sentence instruction for an autonomous agent

> Use this provider as an OpenAI-compatible `/v1/chat/completions` API, default to `reasoning_effort: "none"`, use bounded reasoning only for hard tasks, preserve the API key, keep concurrency around four requests, and never alter server/thread/model settings without validating VRAM, throughput, latency, and the 512-task cgroup budget.


## Available Models on This llama.cpp Provider

The following model aliases are available (or configured to become available after download/restart) on this self-hosted llama.cpp API provider.

| API Alias | Model | Quantization | Approx. File Size | Intended Role |
|---|---|---:|---:|---|
| `qwen38` | Qwen3.8-27B | Q6_K | ~22.56 GB | Dense baseline; strong general-purpose/coding model |
| `qwen36` | Qwen3.6-35B-A3B | UD-Q5_K_M | ~26.46 GB | High-throughput MoE default; excellent concurrency/efficiency |
| `glm47q8` | GLM-4.7-Flash | Q8_0 | ~31.84 GB | Strong GLM-family coding/agentic model; mostly/fully GPU-resident on A100 40 GB |
| `gptoss120` | GPT-OSS-120B | MXFP4 | ~63.4 GB total (2 shards) | Heavyweight reasoning/coding model; requires CPU+GPU offload and will be slower |

### Recommended Usage

- **Default / high concurrency:** `qwen36`
- **Dense reference model:** `qwen38`
- **Agentic/coding comparison model:** `glm47q8`
- **Heavy reasoning / experimental heavyweight:** `gptoss120`

### Important API Behavior

For normal requests, prefer:

```json
"reasoning_effort": "none"