FROM docker.io/library/golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -o /pcap_ring_writer .

FROM docker.io/library/alpine:3.19
RUN apk add --no-cache libcap
COPY --from=builder /pcap_ring_writer /usr/local/bin/pcap_ring_writer
ENTRYPOINT ["/usr/local/bin/pcap_ring_writer"]
