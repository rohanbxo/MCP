# MCP Tool-Response Firewall — API image (rules-only by default).
#
# The ML stack (transformers/torch) is intentionally NOT installed here so the
# image stays small; the firewall runs fully on rules alone. To enable ML,
# install the ".[ml]" extra and mount/copy a trained model into /app/model.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first (better layer caching).
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip && pip install .

# Bring in the demo servers (handy for `scan-server` from inside the container).
COPY servers ./servers

EXPOSE 8000

# Serve the scan API. /health and /scan need no MCP connection.
CMD ["uvicorn", "mcp_firewall.api:app", "--host", "0.0.0.0", "--port", "8000"]
