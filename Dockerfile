# Build stage: compile the cgo-enabled Go binary.
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILDTIME=
RUN CGO_ENABLED=1 go build \
  -ldflags "-X github.com/sr1ch1/webapp-template/internal/version.Version=${VERSION} -X github.com/sr1ch1/webapp-template/internal/version.Commit=${COMMIT} -X github.com/sr1ch1/webapp-template/internal/version.BuildTime=${BUILDTIME}" \
  -o /bin/app ./cmd/app

# Runtime stage: minimal Alpine image with a non-root user.
# The runtime base image is intentionally not pinned: this is a template, and
# pinning would force the maintainer to update the template on every Alpine
# security release. Derived apps should pin to a specific image tag or digest.
FROM alpine:latest
RUN apk add --no-cache ca-certificates \
  && addgroup -S app \
  && adduser -S app -G app
WORKDIR /data
COPY --from=builder /bin/app /bin/app
RUN chown -R app:app /data
USER app
EXPOSE 8080
ENTRYPOINT ["/bin/app"]
