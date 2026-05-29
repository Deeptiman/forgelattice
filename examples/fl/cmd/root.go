package cmd

import (
	"encoding/hex"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

type KeyPairOutput struct {
	Algorithm  string `json:"algorithm"`
	Level      string `json:"level"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type EncapsOutput struct {
	Algorithm        string `json:"algorithm"`
	Level            string `json:"level"`
	CiphertextSize   string `json:"ciphertext_size"`
	SharedSecretSize string `json:"shared_secret_size"`
	SharedSecret     string `json:"shared_secret"`
	Ciphertext       string `json:"ciphertext"`
}

type DecapsOutput struct {
	Algorithm    string `json:"algorithm"`
	Level        string `json:"level"`
	SharedSecret string `json:"shared_secret"`
}

type SignatureOutput struct {
	Algorithm string `json:"algorithm"`
	Level     string `json:"level"`
	Size      string `json:"size"`
	Signature string `json:"signature"`
}

var rootCmd = &cobra.Command{
	Short: "Small Module Lattice CLI application using forgelattice library",
	Long: `Forge Lattice CLI
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
	rootCmd.AddCommand(kyberCmd, dilithiumCmd)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		panic(err)
	}
	return b
}
