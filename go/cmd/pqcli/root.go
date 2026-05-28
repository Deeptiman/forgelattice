package pqcli

import (
	"encoding/hex"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

var rootCmd = &cobra.Command{
	Short: "Small PQC CLI application using forgelattice library",
	Long: `Post Quantum CLI
A command-line tool to demonstrate and use the ForgeLattice PQC library.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(kyberKeyGenCmd, kyberEncapsCmd, kyberDecapsCmd)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		panic(err)
	}
	return b
}
