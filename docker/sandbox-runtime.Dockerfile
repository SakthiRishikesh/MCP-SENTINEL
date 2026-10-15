# MCP-Sentinel sandbox runtime: the image every shadow (pre-flight) run starts from.
#
# Node + npm (for npx servers) and Python + uv (for uvx servers) and nothing else: no shell
# utilities such as curl or wget, no compilers. Servers run as an unprivileged user with no
# network, a read-only root filesystem and all capabilities dropped (see sandbox/shadow.py).
#
# Built by Sentinel (dashboard: Sandbox -> Build image, or automatically on first use):
#   docker build -t mcp-sentinel/sandbox:1 -f docker/sandbox-runtime.Dockerfile docker/
# Base images can be swapped for a mirror with SENTINEL_SANDBOX_NODE_IMAGE / _PYTHON_IMAGE.
ARG NODE_IMAGE=node:22-slim
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${NODE_IMAGE} AS node

FROM ${PYTHON_IMAGE}
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
# optional corporate CA for the build (Sentinel copies it here when one is configured)
COPY sandbox-ca/ /opt/sentinel/ca/
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && if [ -s /opt/sentinel/ca/ca.crt ]; then export PIP_CERT=/opt/sentinel/ca/ca.crt; fi \
 && pip install --no-cache-dir --disable-pip-version-check uv \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin sandbox \
 && node --version && uv --version
LABEL org.opencontainers.image.title="mcp-sentinel-sandbox" \
      org.opencontainers.image.description="Runtime for MCP-Sentinel shadow (pre-flight) tool calls"
USER 10001
WORKDIR /home/sandbox
