FROM golang:1.26.5-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -o /goff ./cmd/goff

FROM alpine:3.23
RUN apk add --no-cache ca-certificates libxslt
COPY --from=builder /goff /usr/local/bin/goff
ENTRYPOINT ["/usr/local/bin/goff"]
