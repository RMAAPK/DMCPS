# DMCPS — C++ MCP sandbox

DMCPS is a C++20 server that exposes filesystem and shell tools through the Model Context Protocol. It provides an authenticated admin dashboard, MCP over legacy SSE (`/sse`) and stateless JSON-RPC HTTP (`/mcp`), plus stdio mode for local MCP clients. The intended deployment boundary is a restricted container; the directory list controls the filesystem MCP tools and each shell command's working directory, while Docker isolation limits what arbitrary shell commands can see.

## Build and test

The easiest supported route is Docker:

```sh
cp .env.example .env
# Edit .env; set a unique ADMIN_PASSWORD (at least 12 characters).
mkdir -p projects
docker compose up --build -d
```

Open `http://localhost:3000` and sign in with `ADMIN_USERNAME` / `ADMIN_PASSWORD`. Add `/workspace` or a narrower directory under it. Writes are only enabled when the corresponding option is checked. For HTTPS, set `DOMAIN_NAME` to a DNS name pointing at the host and start Caddy with `docker compose --profile tls up --build -d`; otherwise the app port is exposed directly for local testing.

To build on Debian/Ubuntu, install `cmake`, a C++20 compiler, `git`, `nlohmann-json3-dev`, and `libcurl4-openssl-dev` (CMake fetches the pinned cpp-httplib source), then:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

HTTP mode requires `ADMIN_PASSWORD` with at least 12 characters. For local HTTP development, set writable local paths, for example `ADMIN_PASSWORD='a-unique-local-secret' CONFIG_PATH="$PWD/config/allowed_dirs.json" WORKSPACE_DIR="$PWD/projects" BACKUP_DIR="$PWD/backups" ./build/dmcps`. Run `./build/dmcps --stdio` for newline-delimited MCP JSON-RPC over stdin/stdout. `PORT`, `WORKSPACE_DIR`, `BACKUP_DIR`, and `CONFIG_PATH` can be overridden with environment variables.

## MCP tools

- `read_file`, `write_file`, and `list_directory` operate only under an explicitly approved directory. Writes additionally require write access.
- `run_shell_command` starts `/bin/sh` as the unprivileged container user, with a 30-second limit and a 64 KiB output cap. Its `cwd` must be approved. Shell commands are inherently not constrained to that directory: they can access anything visible inside the container. Do not mount sensitive host paths into the container.
- `ph_graphql_query` is available when `PH_ACCESS_TOKEN` is set.

The dashboard is protected by HTTP Basic Auth. MCP routes require `Authorization: Bearer <MCP_API_KEY>`; a query `key` is accepted only for older clients. If no `MCP_API_KEY` is set, a random key is generated and stored in `CONFIG_PATH`. The dashboard displays it only after admin authentication. The health endpoint `/healthz` is public.

Existing `allowedDirectories` config files are migrated to the new `directorySettings` format with writes and backups disabled. The first start has no approved directories, so file/shell tools remain locked until an admin adds paths.

## Backups

When a directory has backups enabled, the server copies an existing file to `BACKUP_DIR` before replacing it. Optional remote uploads use `HF_BUCKET_URL` plus `HF_API_KEY` and HTTPS only. The previous whole-container root snapshot/restore behavior is intentionally not carried over: extracting a remote archive into `/` was unsafe.

## Container security

The image runs as UID 10001, has a read-only root filesystem in Compose, drops Linux capabilities, and uses `no-new-privileges`. Only `./projects` is mounted as workspace data; config and backups use separate named volumes. On Linux hosts, make the project directory writable by UID 10001 (or deliberately change the container UID to match your account). Keep mounts narrow. Because shell commands are arbitrary by design, the container boundary—not the directory UI—is the final isolation layer. Never run this container privileged or mount the host root, Docker socket, credentials, or other sensitive locations.

`docker-compose.yml` includes Caddy as an optional TLS reverse proxy. Set `DOMAIN_NAME` and point DNS at the machine before exposing it publicly. Configure `CORS_ORIGIN` narrowly if browser clients need cross-origin access.

## Deployments

The Dockerfile is the canonical build for Cloud Run, Railway, and Render. The supplied Render configuration uses the free plan and therefore stores its config/backups on ephemeral storage; use a persistent disk if you need those settings to survive instance replacement. `cloudbuild.yaml` expects Secret Manager secrets named `dmcps-admin-password` and `dmcps-mcp-api-key`; create them and grant the Cloud Build/Cloud Run service accounts access before deploying. Vercel's previous serverless Node configuration was removed because it cannot host this persistent C++ MCP/SSE server in the same way.

## License

MIT License; see [LICENSE](LICENSE).
