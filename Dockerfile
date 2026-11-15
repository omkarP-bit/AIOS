# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.23
ARG PYTHON_VERSION=3.12
ARG OPA_VERSION=0.63.0

FROM golang:${GO_VERSION}-bookworm AS gobuild
WORKDIR /src
COPY core/go.mod ./
RUN go mod download
COPY core/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/aios ./cmd/aios \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/aiosd ./cmd/aiosd

# The Go policy client executes `opa eval` locally, so the binary must be in
# the runtime image rather than a separate OPA service.
FROM openpolicyagent/opa:${OPA_VERSION} AS opa

FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ARG AIOS_UID=1000
ARG AIOS_GID=1000

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AIOS_API_HOST=0.0.0.0 \
    AIOS_POLICY_DIR=/app/aios/policies \
    AIOS_OPA_BINARY=/usr/local/bin/opa \
    AIOS_QUARANTINE_DIR=/state/quarantine \
    AIOS_LEDGER_PATH=/state/ledger.jsonl

RUN apt-get update \
 && apt-get install --no-install-recommends -y ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid "${AIOS_GID}" aios \
 && useradd --uid "${AIOS_UID}" --gid aios --create-home \
      --shell /usr/sbin/nologin aios

WORKDIR /app
COPY pyproject.toml README.md ./
COPY aios ./aios
RUN pip install --no-cache-dir --no-compile .

COPY --from=gobuild /out/aios /usr/local/bin/aios
COPY --from=gobuild /out/aiosd /usr/local/bin/aiosd
COPY --from=opa /opa /usr/local/bin/opa
RUN chmod 0755 /usr/local/bin/opa \
 && mkdir -p /state \
 && chown -R aios:aios /app /state

USER aios
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).read()"]

CMD ["aiosd"]
