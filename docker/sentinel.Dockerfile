FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Runtimes for local (stdio) MCP servers: npx (Node.js) and uvx (uv).
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv
COPY pyproject.toml README.md ./
COPY sentinel ./sentinel
COPY identity ./identity
COPY policy ./policy
COPY risk ./risk
COPY monitoring ./monitoring
COPY integrity ./integrity
COPY workflow ./workflow
COPY mfa ./mfa
COPY dataflow ./dataflow
COPY sandbox ./sandbox
COPY mcp_servers ./mcp_servers
RUN pip install --no-cache-dir .
EXPOSE 8443
CMD ["uvicorn", "sentinel.app:app", "--host", "0.0.0.0", "--port", "8443"]
