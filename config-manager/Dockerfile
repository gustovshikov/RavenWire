FROM docker.io/library/elixir:1.19.5-otp-28-alpine

RUN apk add --no-cache build-base git nodejs npm inotify-tools

WORKDIR /app

# Install hex + rebar
RUN mix local.hex --force && mix local.rebar --force

# Copy mix files and fetch deps first (layer cache)
COPY mix.exs mix.lock ./
RUN MIX_ENV=dev mix deps.get

# Copy full source
COPY . .

# Build Tailwind assets
RUN cd assets && npm ci && npm run build

# Compile
RUN MIX_ENV=dev mix compile

# Data directory for SQLite DB and CA
RUN mkdir -p /data/ca

EXPOSE 4000

ENTRYPOINT ["/bin/sh", "-c", "mix ecto.create --quiet; mix ecto.migrate --quiet; exec mix phx.server"]
