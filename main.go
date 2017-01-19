// Copyright 2015 The appc Authors
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

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var BuildTime string
var BuildVersion string
var BuildCommit string

type ACServer struct {
	Storage ACStorage
	Api     ACApi
}

func (acs *ACServer) init() error {
	if err := acs.Storage.init(); err != nil {
		return err
	}
	if err := acs.Api.init(&acs.Storage); err != nil {
		return err
	}
	return nil
}

func loadConfig(configPath string, acserver *ACServer) error {
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("Failed to read configuration file : %s, %v", configPath, err)
	}

	err = yaml.Unmarshal(file, acserver)
	if err != nil {
		return fmt.Errorf("Invalid configuration format : %s, %v", configPath, err)
	}

	return nil
}

func main() {
	var version bool

	rootCmd := &cobra.Command{
		Use: "acserver config.yml",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if version {
				fmt.Println("acserver")
				fmt.Println("Version :", BuildVersion+"-"+BuildCommit)
				fmt.Println("Build Time :", BuildTime)
				os.Exit(0)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			var acserver ACServer
			if len(args) > 1 {
				fmt.Fprintf(os.Stderr, "acserver require only a configuration file as argument\n")
				os.Exit(1)
			} else if len(args) == 1 {
				if err := loadConfig(args[0], &acserver); err != nil {
					fmt.Fprintf(os.Stderr, "Cannot start, failed to load configuration\n")
					os.Exit(1)
				}
			} else {
				fmt.Fprintf(os.Stderr, "No configuration file set, using only default values\n")
			}
			acserver.init()
			acserver.Storage.start()
			acserver.Api.Start()
		},
	}

	rootCmd.PersistentFlags().BoolVarP(&version, "version", "V", false, "Display version")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to process args\n")
		os.Exit(1)
	}

}
