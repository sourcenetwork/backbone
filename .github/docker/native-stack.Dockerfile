# syntax=docker/dockerfile:1
# The CI compiler runs on Ubuntu 24.04; use the same runtime ABI.
FROM ubuntu:24.04 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libstdc++6 libssl3t64 netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

FROM runtime AS verad
COPY --chmod=755 runtime-binary /usr/local/bin/verad
ENTRYPOINT ["verad"]

FROM runtime AS orbis-node
COPY --chmod=755 runtime-binary /usr/local/bin/orbis-node
ENTRYPOINT ["orbis-node"]
