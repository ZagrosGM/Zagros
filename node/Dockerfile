# Dedicated Zagros Node data-plane image.
# Build from the matching, tested panel release so drivers and their OS runtime
# stay byte-for-byte aligned; the panel process is never started here.
ARG ZAGROS_VERSION=v1.0.0-alpha.8.9
ARG TARGETARCH
FROM ghcr.io/zagrosgm/zagros:${ZAGROS_VERSION}

LABEL org.opencontainers.image.title="Zagros Node" \
      org.opencontainers.image.source="https://github.com/ZagrosGM/Zagros" \
      org.opencontainers.image.description="Authenticated multi-core Zagros data-plane agent"

COPY node/entrypoint.sh /usr/local/bin/zagros-node-entrypoint
# Keep the agent entry surface aligned with this source revision even when the
# runtime base is the matching released panel image.
COPY app/node_agent/app.py /code/app/node_agent/app.py
RUN chmod 0755 /usr/local/bin/zagros-node-entrypoint \
 && mkdir -p /var/lib/zagros-node /var/lib/zagros/cores \
 && chmod 0700 /var/lib/zagros-node

ENV ZAGROS_NODE_HOST=0.0.0.0 \
    ZAGROS_NODE_PORT=62050 \
    ZAGROS_NODE_DATA=/var/lib/zagros-node \
    ZAGROS_NODE_TLS_CERT=/var/lib/zagros-node/tls/node.crt \
    ZAGROS_NODE_TLS_KEY=/var/lib/zagros-node/tls/node.key \
    PYTHONUNBUFFERED=1

EXPOSE 62050
VOLUME ["/var/lib/zagros-node", "/var/lib/zagros/cores"]
# Rehydrating several enabled cores (notably SoftEther) can take over a minute;
# do not mark a recovering node unhealthy before application startup finishes.
HEALTHCHECK --interval=30s --timeout=3s --start-period=180s --retries=3 \
  CMD python -c 'import socket,os; s=socket.create_connection(("127.0.0.1",int(os.getenv("ZAGROS_NODE_PORT","62050"))),3); s.close()'
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/zagros-node-entrypoint"]
CMD ["python", "-m", "app.node_agent"]
