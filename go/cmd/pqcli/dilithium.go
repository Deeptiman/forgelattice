package pqcli

import (
	"encoding/hex"
	"fmt"
	"github.com/Deeptiman/forgelattice/go/crypto/sign/dilithium"
	"github.com/spf13/cobra"
)

var dilithiumCmd = &cobra.Command{
	Use:   "dilithium",
	Short: "CRYSTALS-Dilithium DSA operations",
}

var dilithiumKeyGenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate Dilithium keypair",
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

		d := sign.WithFIPS204(sign.ToLevel(fmt.Sprintf("ML-DSA-%s", level)))
		pk, sk := d.GenerateKeyPair(seedBytes)

		fmt.Println("✅ Dilithium KeyGen Successful")
		fmt.Printf("Security Level : %s\n", level)
		fmt.Printf("Public Key  : %s\n", hex.EncodeToString(d.MarshalPublicKey(pk)))
		fmt.Printf("Private Key : %s\n", hex.EncodeToString(d.MarshalPrivateKey(sk)))
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
		d := sign.WithFIPS204(sign.ToLevel(fmt.Sprintf("ML-DSA-%s", level)))
		signature := d.Sign(sk, msgBytes, rnd)

		fmt.Println("✅ Dilithium Sign Successful")
		fmt.Printf("Signature (%d bytes): %s\n", len(signature), hex.EncodeToString(signature))
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
		d := sign.WithFIPS204(sign.ToLevel(fmt.Sprintf("ML-DSA-%s", level)))
		valid := d.Verify(pkBytes, sigBytes, msgBytes)
		if valid {
			fmt.Println("✅ Signature is VALID")
		} else {
			fmt.Println("❌ Signature is INVALID")
		}
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
