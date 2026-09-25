# Owned synthetic vulnerable fixture. Never deploy outside an isolated range.
FROM python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10002 fixture
COPY src/ .
USER fixture
CMD ["python", "app.py"]
