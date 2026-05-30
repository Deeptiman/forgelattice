package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Deeptiman/forgelattice/crypto/dsa"
	"github.com/spf13/cobra"
	"strings"
)

var dilithiumCmd = &cobra.Command{
	Use:   "dsa",
	Short: "CRYSTALS-Dilithium (ML-DSA) operations",
}

var dilithiumKeyGenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a Dilithium keypair",
	Run: func(cmd *cobra.Command, args []string) {
		seed, _ := cmd.Flags().GetString("seed")
		level, _ := cmd.Flags().GetString("level")

		if seed == "" {
			fmt.Println("Error: --seed flag is required")
			cmd.Usage()
			return
		}

		if level == "" {
			fmt.Println("Error: --level is required")
			cmd.Usage()
			return
		}

		var seedBytes [32]byte
		seedHex := mustHex(seed)
		copy(seedBytes[:], seedHex)

		d := dsa.WithFIPS204(dsa.ToLevel(fmt.Sprintf("ML-DSA-%s", level)))
		pk, sk := d.GenerateKeyPair(seedBytes)

		fmt.Println("✅ Dilithium KeyGen Successful")
		output := KeyPairOutput{
			Algorithm:  "ML-DSA",
			Level:      level,
			PublicKey:  strings.ToUpper(hex.EncodeToString(d.MarshalPublicKey(pk))),
			PrivateKey: strings.ToUpper(hex.EncodeToString(d.MarshalPrivateKey(sk))),
		}
		data, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(data))
	},
}

var dilithiumSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a message using Dilithium",
	Run: func(cmd *cobra.Command, args []string) {
		skHex, _ := cmd.Flags().GetString("privKey")
		message, _ := cmd.Flags().GetString("message")
		level, _ := cmd.Flags().GetString("level")

		if skHex == "" {
			fmt.Println("Error: --privKey is required")
			cmd.Usage()
			return
		}

		if message == "" {
			fmt.Println("Error: --message is required")
			cmd.Usage()
			return
		}

		if level == "" {
			fmt.Println("Error: --level is required")
			cmd.Usage()
			return
		}

		sk := mustHex(skHex)
		msgBytes := mustHex(message)
		var rnd [32]byte
		d := dsa.WithFIPS204(dsa.ToLevel(fmt.Sprintf("ML-DSA-%s", level)))
		signature := d.Sign(sk, msgBytes, rnd)

		fmt.Println("✅ Dilithium Sign Successful")
		output := SignatureOutput{
			Algorithm: "ML-DSA",
			Level:     level,
			Size:      fmt.Sprintf("(%d bytes)", len(signature)),
			Signature: strings.ToUpper(hex.EncodeToString(signature)),
		}
		data, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(data))
	},
}

var dilithiumVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a signature using Dilithium",
	Run: func(cmd *cobra.Command, args []string) {
		pkHex, _ := cmd.Flags().GetString("pubKey")
		sigHex, _ := cmd.Flags().GetString("signature")
		message, _ := cmd.Flags().GetString("message")
		level, _ := cmd.Flags().GetString("level")

		if pkHex == "" {
			fmt.Println("Error: --pubKey is required")
			cmd.Usage()
			return
		}

		if sigHex == "" {
			fmt.Println("Error: --signature is required")
			cmd.Usage()
			return
		}

		if message == "" {
			fmt.Println("Error: --message is required")
			cmd.Usage()
			return
		}

		if level == "" {
			fmt.Println("Error: --level is required")
			cmd.Usage()
			return
		}

		pkBytes := mustHex(pkHex)
		msgBytes := mustHex(message)
		sigBytes := mustHex(sigHex)
		d := dsa.WithFIPS204(dsa.ToLevel(fmt.Sprintf("ML-DSA-%s", level)))
		valid := d.Verify(pkBytes, sigBytes, msgBytes)
		output := VerifyOutput{
			Algorithm: "ML-DSA",
			Level:     level,
		}
		if valid {
			output.SigState = "✅ Signature is VALID"
		} else {
			output.SigState = "❌ Signature is INVALID"
		}
		data, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(data))
	},
}

func init() {
	// KeyGen flags
	dilithiumKeyGenCmd.Flags().String("seed", "", "seed (hex)")
	dilithiumKeyGenCmd.Flags().String("level", "44", "Security levels: 44, 65, 87")

	// SignGen flags
	dilithiumSignCmd.Flags().String("privKey", "", "Private key (hex)")
	dilithiumSignCmd.Flags().String("message", "", "message (hex)")
	dilithiumSignCmd.Flags().String("level", "44", "Security levels: 44, 65, 87")

	// Verify flags
	dilithiumVerifyCmd.Flags().String("pubKey", "", "Public key (hex)")
	dilithiumVerifyCmd.Flags().String("signature", "", "Signature (hex)")
	dilithiumVerifyCmd.Flags().String("message", "", "message (hex)")
	dilithiumVerifyCmd.Flags().String("level", "44", "Security levels: 44, 65, 87")

	dilithiumCmd.AddCommand(dilithiumKeyGenCmd, dilithiumSignCmd, dilithiumVerifyCmd)
}
