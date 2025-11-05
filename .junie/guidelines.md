# Project Development Guidelines — cbomkit-theia

This document captures project-specific knowledge to speed up advanced development and debugging. It focuses on build/configuration, testing, and conventions unique to this repository.


## 1) Build and Configuration

- Go toolchain
  - Required Go version per `go.mod`: `go 1.24`. We successfully ran tests with Go `1.25.3`. Keep `GO111MODULE=on` (default in recent Go).
  - Module path: `github.com/cbomkit/cbomkit-theia`.

- Build
  - Fast local build (no CGO required for core binary):
    ```bash
    go mod download
    go build ./...
    # or build only the CLI
    go build -o cbomkit-theia
    ```
  - Docker build (aligns with CI and README):
    ```bash
    docker build -t cbomkit-theia .
    ```

- Running the CLI (examples):
  - Directory scan:
    ```bash
    ./cbomkit-theia dir testdata/secrets/dir > enriched_cbom.json
    ```
  - Image scan (requires local Docker daemon access):
    ```bash
    ./cbomkit-theia image nginx -p certificates -p secrets > enriched_cbom.json
    ```

- Configuration file
  - Location: `$HOME/.cbomkit-theia/config.yaml`. Created automatically on first run.
  - Plugins: by design, the app restores all built-in plugins if they were removed from the config. To disable plugins for a single run, prefer CLI flags: `-p certificates -p secrets`.
  - Schema validation: the `--schema` flag defaults to `provider/cyclonedx/bom-1.6.schema.json`.

- External runtimes
  - Docker/OCI: For `image` scans, the Docker daemon or an OCI registry must be reachable. Respect `DOCKER_HOST` if you run outside the default socket.
  - Secrets plugin leverages `gitleaks` via Go dependency `github.com/zricethezav/gitleaks/v8`; no separate binary installation is required when using the provided module.


## 2) Testing

- Test runner
  - Standard Go tests. Run everything:
    ```bash
    go test ./...
    ```

- Structure and packages with tests
  - Packages with tests include (as of writing):
    - `github.com/IBM/cbomkit-theia` (root)
    - `provider/cyclonedx`
    - `scanner/plugins/certificates`
    - `scanner/plugins/javasecurity`
    - `scanner/plugins/secrets`
  - Testdata is under `testdata/` and `provider/cyclonedx/testfiles/` and is safe to reference using relative paths from the package directory.

- Adding tests
  - Place `_test.go` files in the target package directory. Use only standard `testing` unless there is a strong reason otherwise. `testify` is available in `go.mod` if you want richer assertions (`github.com/stretchr/testify`), but existing tests primarily use the standard library.
  - Keep tests hermetic: prefer in-repo `testdata` fixtures over external network calls. For Docker-related code, prefer mocks or sample layers where possible.

- Example: create and run a simple test
  - We validated the process with a temporary unit test targeting `utils.StandardizeString`.
  - Minimal example you can adapt in any package:
    ```go
    package utils

    import "testing"

    func TestStandardizeString_Guidelines(t *testing.T) {
        in := "rsa-2048_key"
        got := StandardizeString(in)
        want := "RSA"
        if got != want {
            t.Fatalf("StandardizeString(%q) = %q; want %q", in, got, want)
        }
    }
    ```
  - Command to run:
    ```bash
    go test ./...
    ```
  - The above test passed locally during guideline preparation and was removed afterwards to keep the repository clean.

- CI notes
  - GitHub Actions workflow exists at `.github/workflows/build.yml`. It performs module caching and a full test run. Align local changes with CI Go version ranges (>= 1.24).


## 3) Development and Debugging Notes

- Plugin system
  - Implement new plugins by satisfying `scanner/plugins.Plugin` and registering the constructor in `scanner/scanner.go` (`GetAllPluginConstructors`). Ensure each plugin operates purely on the provided filesystem or image abstraction and does not require network by default.
  - Current built-in plugins:
    - `certificates`: scans X.509 certificates; extracts public key material and signature algorithms.
    - `javasecurity`: parses `java.security` and maps `jdk.tls.disabledAlgorithms` into a confidence score overlay for CBOM components.
    - `secrets`: secret and key detection via gitleaks.

- Code style
  - Follow idiomatic Go formatting (`gofmt`, `goimports`). Keep logging consistent with `logrus` where used. Public APIs should carry short, focused doc comments. Mirror patterns used in `scanner/plugins/*`.

- Error handling
  - Prefer returning concrete errors over logging fatals inside libraries. The CLI layer (`cmd/*`) should handle user-facing messages; lower layers should remain reusable.

- Determinism
  - Tests should be deterministic across platforms. When file-order matters, sort slices before comparison. Utilities exist in `utils/*`.

- BOM handling
  - The CycloneDX provider resides in `provider/cyclonedx`. When modifying schemas or parsing logic, update fixtures in `provider/cyclonedx/testfiles` and extend `bom_test.go` to cover corner-cases.

- Docker/image providers
  - For features touching Docker/OCI, ensure code paths gracefully degrade when the daemon is unavailable. Gate integration tests behind build tags if they would require a live daemon.

- Security
  - Be mindful of the security disclaimer in `README.md`: the tool reads files based on user input and may echo some contents to stderr. Avoid logging sensitive material in production paths; use redaction utilities where appropriate.


## 4) Quick Commands Reference

- Full test run: `go test ./...`
- Lint/format (suggested): `gofmt -s -w . && go vet ./...`
- Build CLI: `go build -o cbomkit-theia`
- Docker build: `docker build -t cbomkit-theia .`


## 5) Environment Assumptions

- macOS/Linux with recent Go (>= 1.24). Apple Silicon works (tests run under `darwin/arm64`).
- Access to Docker is optional unless scanning images. For directory scans and parsing CBOMs, Docker is not required.
