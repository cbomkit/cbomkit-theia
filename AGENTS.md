# Repository Guidelines

## Project Structure & Module Organization

`cbomkit-theia.go` starts the CLI; `cmd/` defines its Cobra commands. `scanner/` coordinates scans, with detectors under `scanner/plugins/` and parsing helpers in sibling packages. `provider/` handles filesystem, container image, and CycloneDX BOM input and output. Shared helpers live in `utils/`. Keep sample inputs under `testdata/`, package-specific fixtures beside their tests (for example, `provider/cyclonedx/testfiles/`), and runtime data beside its consumer (such as `scanner/tls/ciphersuites.json`).

## Build, Test, and Development Commands

Use the Go version declared in `go.mod`. Run `go mod download` to fetch dependencies and `go build ./...` to compile all packages. `go run . dir ./testdata/empty/dir` exercises the directory CLI; `go run . image <image>` scans a container image and may require Docker access. Run `go test ./...` for the full suite and `go vet ./...` for static checks. CI also builds and tests every package. Run `go mod tidy` when dependencies change, and review the resulting `go.mod` and `go.sum` diff.

## Coding Style & Naming Conventions

Format Go code with `go fmt ./...`; follow standard Go tabs, package names, and exported identifier conventions. Use descriptive plugin directories and keep each plugin's implementation and tests together. New Go files need the repository's PQCA Apache 2.0 license header; see `CONTRIBUTING.md` for the `addlicense` command.

## Testing Guidelines

Place tests in `*_test.go` files next to the code they cover, using `TestXxx` functions and `t.Run` for cases. Existing tests use Go's `testing` package and `testify` assertions. Add regression cases for changed scanner behavior and reusable fixtures under `testdata/`. Run `go test ./...` before opening a pull request. No coverage threshold is documented.

## Commit & Pull Request Guidelines

Recent commits use concise subjects, often with a type and scope such as `fix(scanner): cap file reads` or `chore(deps): update module`; issue references commonly appear as `(#123)`. Keep commits focused. In pull requests, explain the behavior change, link the relevant issue, and list build and test results. Include a short CLI output example when the generated BOM or command behavior changes. Follow `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`.

## Security & Configuration

Scanner output and logs may expose contents of scanned files. Use synthetic fixtures, and avoid committing real credentials. Configuration and ignore pattern behavior are described in `README.md`; check both when changing file discovery.
