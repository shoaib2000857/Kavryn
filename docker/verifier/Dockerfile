# The clean-room verifier image. Deliberately a SEPARATE image and a
# SEPARATE non-root identity from docker/analysis-worker (uid 10001,
# user "analysis"): docs/DECISIONS.md ADR-009 requires candidate
# generation and verification to never share identity or writable
# state. This image never receives model/provider code and never makes
# a network call at run time.
FROM python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
RUN apt-get update \
    && apt-get install -y --no-install-recommends patch \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask==3.1.3 pytest==9.1.1
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN useradd --create-home --uid 10003 verifier
USER verifier
WORKDIR /home/verifier
