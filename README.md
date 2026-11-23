# CertWatch

Concurrent TLS certificate, DNS and endpoint-latency monitor built with Go 1.22 and a zero-build Vanilla JavaScript UI.

## Deploy on Vercel
Import this repository into Vercel. The static dashboard is served from `public/`; Go functions live under `api/`. No Node build step is required.

## Local development
```sh
go run ./cmd/server
```
Open http://localhost:8080. (The optional local server is included in the source tree.) Verify with `gofmt -w api/targets/index.go api/probe/index.go`, `go vet ./api/...`, and `go test ./...`.

## API
- `GET /api/targets` — seeded and in-memory registered targets
- `POST /api/targets` — register a hostname (serverless memory is instance-local)
- `POST /api/probe` — bounded concurrent TLS checks

Probe targets are restricted to public IP ranges after DNS resolution. This protects the deployment from requests to private infrastructure and cloud metadata endpoints. Results are diagnostic snapshots, not a substitute for a full PKI audit.
