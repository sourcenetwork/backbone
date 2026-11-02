FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libstdc++6 libssl3t64 netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

ARG EXECUTABLE
COPY ${EXECUTABLE} /usr/local/bin/${EXECUTABLE}
RUN ldd /usr/local/bin/${EXECUTABLE} > /tmp/linkage && \
    ! grep -F 'not found' /tmp/linkage && rm /tmp/linkage

ENTRYPOINT ["orbis-node"]
