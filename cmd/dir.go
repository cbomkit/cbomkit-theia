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
	"io"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/cbomkit/cbomkit-theia/scanner"
	"github.com/spf13/cobra"
	"go.uber.org/dig"
)

var dirCommand = &cobra.Command{
	Use:   "dir",
	Short: "Analyze cryptographic assets in a directory",
	Long: `Analyze cryptographic assets in a directory

Supported image/filesystem sources:
- local directory

Examples:
cbomkit-theia dir my/cool/directory
`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		container := dig.New()

		if err := container.Provide(func() filesystem.Filesystem {
			return filesystem.NewPlainFilesystem(args[0])
		}); err != nil {
			log.Error("Could not scan dir: ", err)
			return
		}

		if err := container.Provide(func() string {
			return bomFilePath
		}, dig.Name("bomFilePath")); err != nil {
			log.Error("Could not scan dir: ", err)
			return
		}

		if err := container.Provide(func() io.Writer {
			return os.Stdout
		}); err != nil {
			log.Error("Could not scan dir: ", err)
			return
		}

		if err := container.Invoke(scanner.RunScan); err != nil {
			log.Error("Could not scan dir: ", err)
			return
		}
	},
}
