package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/version"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print eyeexam version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("eyeexam", version.String())
			return nil
		},
	}
}
