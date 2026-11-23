# CertWatch

Concurrent TLS certificate, DNS and endpoint-latency monitor built with Go 1.22 and a zero-build Vanilla JavaScript UI.

## Deploy on Vercel
Import this repository into Vercel. The dashboard is served from `public/`; Go serverless functions are under `api/`. No Node runtime, package manager, or frontend build step is required.

## Verification
```sh
gofmt -w api/targets/index.go api/probe/index.go
go vet ./api/...
go test ./...
python -m json.tool vercel.json
```

## API
- `GET /api/targets` — seeded and in-memory registered targets
- `POST /api/targets` — register a hostname
- `POST /api/probe` — bounded concurrent TLS checks

**Deployment note:** target registration uses process memory. Vercel may start multiple function instances and recycle them, so custom targets are not durable across cold starts. Add a persistent database before relying on registration as long-term inventory.

Probe targets are restricted to public IP ranges after DNS resolution to prevent requests to private infrastructure and cloud metadata endpoints. Results are diagnostic snapshots, not a substitute for a full PKI audit.
