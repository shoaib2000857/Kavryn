# Fixture: path-traversal-v1

An intentionally vulnerable Python web service used as the Aegis Defender
MVP scenario fixture (`docs/MVP_AND_ROADMAP.md`). It exists **only** to
be scanned, exploited-in-replay, contained, patched, and verified by
Aegis inside isolated local ranges — never to be deployed, exposed to a
network beyond the range, or used against any system this project does
not own.

## Layout

```text
src/            the deployable source only (what a patch candidate touches)
public_tests/   legitimate-behavior tests, visible to whatever generates a patch
hidden_tests/   exploit-replay and regression tests, mounted only into the
                clean-room verifier (docs/DECISIONS.md ADR-009) — never
                copied into the disposable patch workspace
```

## Vulnerability

`src/app.py`'s `/download` endpoint joins an unsanitized `filename`
query parameter onto a base directory and serves the result (CWE-22,
path traversal). A request such as:

```text
GET /download?filename=../../../../etc/passwd
```

escapes the intended `files/` directory. This is the reproducible
finding Aegis's static-analysis adapters (Change 5) locate, the
vulnerability its runtime range (Change 7) attack replay exercises, and
what its repair loop (Change 6) patches and its clean-room verifier
checks against `hidden_tests/test_exploit_replay.py`.

## Expected fix

Resolve the requested path with `werkzeug.utils.safe_join` (or an
equivalent canonicalize-and-prefix-check) and reject any request that
resolves outside `BASE_DIR`, instead of a bare `os.path.join`.

## Running locally (manual, outside Aegis)

```bash
cd src && pip install -r ../requirements.txt
python app.py
curl 'http://127.0.0.1:8080/download?filename=welcome.txt'      # intended use
curl 'http://127.0.0.1:8080/download?filename=../requirements.txt'  # the vulnerability
```

## Authorized use only

This fixture is part of the Aegis Defender project and is only for use
by this project's own automated analysis and range tooling against
itself, per `SECURITY.md`.
