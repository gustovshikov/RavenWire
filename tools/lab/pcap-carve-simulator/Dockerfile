FROM docker.io/library/golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -o /pcap_carve_simulator .

FROM docker.io/library/alpine:3.19
COPY --from=builder /pcap_carve_simulator /usr/local/bin/pcap_carve_simulator
ENTRYPOINT ["/usr/local/bin/pcap_carve_simulator"]
