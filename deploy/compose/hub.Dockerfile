FROM golang:1.24 AS build
WORKDIR /src
COPY cloud/hub /src
RUN CGO_ENABLED=0 go build -o /insidia-hub ./cmd/insidia-hub

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends wget \
  && rm -rf /var/lib/apt/lists/*
COPY --from=build /insidia-hub /usr/local/bin/insidia-hub
USER nobody
EXPOSE 8081
CMD ["insidia-hub"]
