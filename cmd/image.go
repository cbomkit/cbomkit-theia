// Copyright 2024 IBM
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
	"io"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/IBM/cbomkit-theia/provider/docker"
	"github.com/IBM/cbomkit-theia/provider/filesystem"
	"github.com/IBM/cbomkit-theia/scanner"
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
		value := viper.GetString("docker_host")
		err := os.Setenv("DOCKER_HOST", value)
		if err != nil {
			log.Error("failed to set environment variable 'DOCKER_HOST'.")
			return
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

func init() {
	imageCommand.
		PersistentFlags().
		StringVar(&dockerHost, "docker_host", "", "docker host to use for interacting with images; only set if DOCKER_HOST environment variable is not set; Default: unix:///var/run/docker.sock; Priority: Flag > ENV > Config File > Default")
}
