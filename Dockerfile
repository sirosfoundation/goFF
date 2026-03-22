FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
RUN go build -trimpath -o /goff ./cmd/goff

FROM alpine:3.22
RUN apk add --no-cache ca-certificates libxslt
COPY --from=builder /goff /usr/local/bin/goff
ENTRYPOINT ["/usr/local/bin/goff"]
