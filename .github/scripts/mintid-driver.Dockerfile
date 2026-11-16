FROM mintid/idchaind:tba-interop AS chain
FROM mintid/issuer-agent:tba-interop
USER root
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY --from=chain /usr/bin/idchaind /usr/bin/idchain-genesis /usr/bin/
COPY --chmod=755 mintid-go-dispatch.sh /usr/local/bin/go
