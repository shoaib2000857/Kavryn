# Pinned read-only analysis worker image (docs/TOOLS_AND_SANDBOXES.md
# "Worker classes: Read-only analysis worker"). Built and pinned by
# digest; the source it scans is mounted read-only at container run
# time, never baked into this image.
FROM python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
RUN pip install --no-cache-dir semgrep==1.176.0 bandit==1.9.4
COPY rules/ /opt/aegis/rules/
RUN useradd --create-home --uid 10001 analysis
USER analysis
WORKDIR /home/analysis
