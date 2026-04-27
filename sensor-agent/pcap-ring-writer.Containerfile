FROM docker.io/library/golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /pcap_ring_writer ./cmd/pcap-ring-writer

FROM docker.io/library/alpine:3.19

COPY --from=builder /pcap_ring_writer /usr/local/bin/pcap_ring_writer

ENTRYPOINT ["/usr/local/bin/pcap_ring_writer"]
