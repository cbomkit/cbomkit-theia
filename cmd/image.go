// Copyright 2024 PQCA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/cbomkit/cbomkit-theia/provider/docker"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/cbomkit/cbomkit-theia/scanner"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/dig"
)

var dockerHost string

var imageCommand = &cobra.Command{
	Use:   "image",
	Short: "Analyze cryptographic assets in a container image",
	Long: `Analyze cryptographic assets in a container image

Supported image sources:
- local docker image from docker daemon
- local docker image as TAR archive
- local OCI image as directory
- local OCI image as TAR archive
- OCI image from OCI registry
- docker image from dockerhub registry
- image from singularity

Examples:
cbomkit-theia image nginx`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if os.Getenv("DOCKER_HOST") != "" {
			return
		}
		value := viper.GetString("docker_host")
		if cmd.PersistentFlags().Changed("docker_host") || value != "unix:///var/run/docker.sock" {
			if err := os.Setenv("DOCKER_HOST", value); err != nil {
				log.Error("failed to set environment variable 'DOCKER_HOST'.")
			}
			return
		}
		if host := resolveDockerHostFromContext(); host != "" {
			if err := os.Setenv("DOCKER_HOST", host); err != nil {
				log.Error("failed to set environment variable 'DOCKER_HOST'.")
			}
		}
	},
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		image, err := docker.GetImage(args[0])
		if err != nil {
			log.Error("could not fetch image: ", err)
			return
		}
		if err := prepareImageAndRun(image); err != nil {
			log.Error("could not scan image: ", err)
		}
	},
}

// This function basically extracts all information that is still missing,
// such as the BOM and the schema and runs a scan on the image top layer
func prepareImageAndRun(image docker.ActiveImage) error {
	defer image.TearDown()
	container := dig.New()

	if err := container.Provide(func() filesystem.Filesystem {
		return docker.GetSquashedFilesystem(image)
	}); err != nil {
		return err
	}

	if err := container.Provide(func() string {
		return bomFilePath
	}, dig.Name("bomFilePath")); err != nil {
		return err
	}

	if err := container.Provide(func() io.Writer {
		return os.Stdout
	}); err != nil {
		return err
	}

	if err := container.Invoke(scanner.RunScan); err != nil {
		return err
	}

	return nil
}

// resolveDockerHostFromContext reads the active Docker context configuration
// to determine the Docker host endpoint. This handles cases where the Docker
// socket is at a non-standard path (e.g., Rancher Desktop, Colima, Podman).
func resolveDockerHostFromContext() string {
	dockerConfigDir := os.Getenv("DOCKER_CONFIG")
	if dockerConfigDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dockerConfigDir = filepath.Join(home, ".docker")
	}

	// Read config.json to find the current context
	configBytes, err := os.ReadFile(filepath.Join(dockerConfigDir, "config.json"))
	if err != nil {
		return ""
	}

	var dockerConfig struct {
		CurrentContext string `json:"currentContext"`
	}
	if err := json.Unmarshal(configBytes, &dockerConfig); err != nil {
		return ""
	}

	if dockerConfig.CurrentContext == "" || dockerConfig.CurrentContext == "default" {
		return ""
	}

	// Context metadata is stored at ~/.docker/contexts/meta/<sha256(name)>/meta.json
	hash := sha256.Sum256([]byte(dockerConfig.CurrentContext))
	contextDir := hex.EncodeToString(hash[:])
	metaPath := filepath.Join(dockerConfigDir, "contexts", "meta", contextDir, "meta.json")

	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return ""
	}

	var meta struct {
		Endpoints map[string]struct {
			Host string `json:"Host"`
		} `json:"Endpoints"`
	}
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return ""
	}

	if ep, ok := meta.Endpoints["docker"]; ok && ep.Host != "" {
		return ep.Host
	}
	return ""
}

func init() {
	imageCommand.
		PersistentFlags().
		StringVar(&dockerHost, "docker_host", "", "docker host to use for interacting with images; only set if DOCKER_HOST environment variable is not set; Default: unix:///var/run/docker.sock; Priority: Flag > ENV > Config File > Default")
}
