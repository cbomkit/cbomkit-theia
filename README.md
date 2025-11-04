# CBOMkit-theia

[![GitHub License](https://img.shields.io/github/license/PQCA/cbomkit-theia)](https://opensource.org/licenses/Apache-2.0)

This repository contains CBOMkit-theia: a tool that detects cryptographic assets in container images as well as directories and generates [CBOM](https://cyclonedx.org/capabilities/cbom/).

> [!NOTE] 
> CBOMkit-theia is part of [CBOMkit](https://github.com/PQCA/cbomkit) and meant to run in conjunction with the [Sonar Cryptography Plugin](https://github.com/PQCA/sonar-cryptography) donated to PQCA by IBM Research.

```
 ██████╗██████╗  ██████╗ ███╗   ███╗██╗  ██╗██╗████████╗████████╗██╗  ██╗███████╗██╗ █████╗ 
██╔════╝██╔══██╗██╔═══██╗████╗ ████║██║ ██╔╝██║╚══██╔══╝╚══██╔══╝██║  ██║██╔════╝██║██╔══██╗
██║     ██████╔╝██║   ██║██╔████╔██║█████╔╝ ██║   ██║█████╗██║   ███████║█████╗  ██║███████║
██║     ██╔══██╗██║   ██║██║╚██╔╝██║██╔═██╗ ██║   ██║╚════╝██║   ██╔══██║██╔══╝  ██║██╔══██║
╚██████╗██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██╗██║   ██║      ██║   ██║  ██║███████╗██║██║  ██║
 ╚═════╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝ by IBM Research

CBOMkit-theia analyzes cryptographic assets in a container image or directory.
It is part of cbomkit (https://github.com/PQCA/cbomkit) donated to PQCA by IBM Research.

--> Disclaimer: CBOMkit-theia does *not* perform source code scanning <--
--> Use https://github.com/PQCA/sonar-cryptography for source code scanning <--

Features
- Find certificates in your image/directory
- Find keys in your image/directory
- Find secrets in your image/directory
- Verify the executability of cryptographic assets in a CBOM (requires --bom to be set)
- Output: Enriched CBOM to stdout/console

Supported image/filesystem sources:
- local directory 
- local application with dockerfile (ready to be build)
- local docker image from docker daemon
- local docker image as TAR archive
- local OCI image as directory
- local OCI image as TAR archive
- OCI image from OCI registry
- docker image
- image from singularity

Supported BOM formats (input & output):
- CycloneDXv1.6

Examples:
cbomkit-theia dir my/cool/directory
cbomkit-theia image nginx

Plugin Explanations:
> "certificates": Certificate File Plugin
Find x.509 certificates

> "javasecurity": java.security Plugin
Verify the executability of cryptographic assets from Java code
Adds a confidence level (0-1) to the CBOM components to show how likely it is that this component is actually executable

> "secrets": Secret Detection Plugin
Find secrets & keys (private, public and secret keys)

> "opensslconf": OpenSSL Configuration Plugin
Reads OpenSSL configuration files and checks cipher suites and algorithm configuration

Usage:
  cbomkit-theia [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  dir         Analyze cryptographic assets in a directory
  help        Help about any command
  image       Analyze cryptographic assets in a container image

Flags:
  -b, --bom string        BOM file to be verified and enriched
      --config string     config file (default is $HOME/.cbomkit-theia.yaml)
  -h, --help              help for cbomkit-theia
  -p, --plugins strings   list of plugins to use (default [certificates,javasecurity,secrets,keys,vex])
      --schema string     BOM schema to validate the given BOM (default "provider/cyclonedx/bom-1.6.schema.json")

Use "cbomkit-theia [command] --help" for more information about a command.
```

## Prerequisites

- Go 
  - Version: `1.24` or up
- Docker (or similar container runtimes)
  - Recommended: Set the `DOCKER_HOST` environment variable (default: `unix:///var/run/docker.sock`)

## Running

### Docker

```shell
docker build -t cbomkit-theia . 
# CLI
docker run cbomkit-theia [command] > enriched_CBOM.json
```

### Compiled

```shell
go mod download
go build
./cbomkit-theia [command] > enriched_CBOM.json
```

## Configuration

CBOMkit-theia reads its configuration from `$HOME/.cbomkit-theia/config.yaml`. This file is automatically created on first run.

### Plugins

By default, all available plugins are enabled:
- certificates
- javasecurity
- secrets (private, public and secret keys)
- opensslconf

**Important Note:** The application is configured to ensure all plugins are always available. If you manually edit the configuration file to exclude specific plugins, CBOMkit-theia will detect this and automatically restore all plugins to their default enabled state on the next run. If you need to disable specific plugins for a particular run, use the `-p` flag instead of modifying the config file:

```shell
# Run with only specific plugins
./cbomkit-theia image nginx -p certificates -p secrets
```

## Development

### Plugins
  - `java.security` Configuration Plugin:
    - Searches the filessystem for the `java.security` file and reads the configuration
    - Reads the `jdk.tls.disabledAlgorithms` property and checks if any of the algorithms are used in the given CBOM
    - Based on the results, a confidence level (`confidence_level`) is assigned to the restricted (or not restricted) algorithms in the CBOM
      - A higher confidence level means that component is more likely to be executable
  - OpenSSL Configuration Plugin:
    - Searches the filesystem for OpenSSL configuration files (e.g., `openssl.cnf`)
    - Reads cipher suite configurations and algorithm configurations
  - X.509 Certificate Plugin:_
    - Search the filesystem for X.509 certificates
    - Add the certificates to the CBOM, as well as signature algorithms, public keys and public key algorithms
  - Secret Plugin:
    - Leverages [gitleaks](https://github.com/gitleaks/gitleaks) to find secrets and keys in the data source
    - Add the secrets and keys (private, public and secret keys) to the CBOM

Additional plugins can be added by implementing the `Plugin` interface from [`cbomkit-theia/scanner/plugins`](./scanner/plugins/plugin.go#L41) and adding the plugins constructor to the `GetAllPluginConstructors` function in [`cbomkit-theia/scanner/scanner.go`](./scanner/scanner.go#L58): 

## Security Disclaimer
CBOMkit-theia performs several filesystem reads based on the user input and may print the contents of these files to the stderr console. Do not use this tools on untrusted input or provide the output to untrusted parties.

## Contribution Guidelines

If you'd like to contribute to CBOMkit-theia, please take a look at our [contribution guidelines](CONTRIBUTING.md). By participating, you are expected to uphold our [code of conduct](CODE_OF_CONDUCT.md).

We use [GitHub issues](https://github.com/PQCA/cbomkit-theia/issues) for tracking requests and bugs. For questions start a discussion using [GitHub Discussions](https://github.com/PQCA/cbomkit-theia/discussions).

## License

[Apache License 2.0](LICENSE)