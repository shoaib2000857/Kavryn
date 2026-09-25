# The reversible-containment enforcement point in front of the
# vulnerable fixture (docs/DECISIONS.md ADR-029). A separate pinned
# image and identity from both the analysis-worker and verifier images.
FROM python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
COPY proxy.py /proxy.py
RUN useradd --create-home --uid 10004 rangeproxy
USER rangeproxy
CMD ["python", "/proxy.py"]
