package cmd

import (
	"encoding/hex"
	"fmt"
	kem "github.com/Deeptiman/forgelattice/crypto/kem/kyber"
	"github.com/spf13/cobra"
	"strings"
)

var kyberCmd = &cobra.Command{
	Use:   "kyber",
	Short: "CRYSTALS-Kyber (ML-KEM) operations",
}

var kyberKeyGenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate Kyber keypair",
	Long:  `Generate a Kyber keypair using seed material.`,
	Run: func(cmd *cobra.Command, args []string) {
		zHex, _ := cmd.Flags().GetString("z")
		dHex, _ := cmd.Flags().GetString("d")
		level, _ := cmd.Flags().GetString("level")

		if zHex == "" || dHex == "" {
			fmt.Println("Error: Both --z and --d flags are required")
			cmd.Usage()
			return
		}

		if level == "" {
			fmt.Println("Error: --level is required")
			cmd.Usage()
			return
		}

		zBytes := mustHex(zHex)
		dBytes := mustHex(dHex)
		var seed [64]byte
		copy(seed[:32], dBytes)
		copy(seed[32:], zBytes)

		k := kem.WithFIPS203(kem.ToLevel(fmt.Sprintf("ML-KEM-%s", level)))
		pk, sk := k.GenerateKeyPair(seed[:])
		fmt.Println("✅ Kyber KeyGen Successful")
		fmt.Printf("Private Key  : %s\n", hex.EncodeToString(k.PackPrivateKey(sk)))
		fmt.Printf("Public Key : %s\n", hex.EncodeToString(k.PackPublicKey(pk)))
	},
}

var kyberEncapsCmd = &cobra.Command{
	Use:   "encaps",
	Short: "Encapsulate (KEM Encaps)",
	Run: func(cmd *cobra.Command, args []string) {
		msgHex, _ := cmd.Flags().GetString("message")
		pkHex, _ := cmd.Flags().GetString("pubKey")
		level, _ := cmd.Flags().GetString("level")

		if msgHex == "" {
			fmt.Println("Error: --message is required")
			cmd.Usage()
			return
		}

		if pkHex == "" {
			fmt.Println("Error: --pubKey is required")
			cmd.Usage()
			return
		}

		if level == "" {
			fmt.Println("Error: --level is required")
			cmd.Usage()
			return
		}

		pkBytes, err := hex.DecodeString(pkHex)
		if err != nil {
			fmt.Println("Error: Invalid public key hex")
			return
		}

		msg := mustHex(msgHex)
		k := kem.WithFIPS203(kem.ToLevel(fmt.Sprintf("ML-KEM-%s", level)))
		pk := k.UnPackPublicKey(pkBytes)
		ct, ss := k.Encapsulate(pk, msg)
		ctHex := strings.ToUpper(hex.EncodeToString(ct))
		ssHex := strings.ToUpper(hex.EncodeToString(ss))
		fmt.Println("✅ Kyber Encapsulation Successful")
		fmt.Printf("Ciphertext   (%d bytes): %s\n", len(ctHex), ctHex)
		fmt.Printf("Shared Secret(%d bytes): %s\n", len(ssHex), ssHex)
	},
}

var kyberDecapsCmd = &cobra.Command{
	Use:   "decaps",
	Short: "Decapsulate (Recover shared secret)",
	Run: func(cmd *cobra.Command, args []string) {
		ctHex, _ := cmd.Flags().GetString("ciphertext")
		skHex, _ := cmd.Flags().GetString("privKey")
		level, _ := cmd.Flags().GetString("level")

		if ctHex == "" {
			fmt.Println("Error: --ciphertext is required")
			cmd.Usage()
			return
		}

		if skHex == "" {
			fmt.Println("Error: --privKey is required")
			cmd.Usage()
			return
		}

		if level == "" {
			fmt.Println("Error: --level is required")
			cmd.Usage()
			return
		}

		ct := mustHex(ctHex)
		skBytes := mustHex(skHex)

		k := kem.WithFIPS203(kem.ToLevel(fmt.Sprintf("ML-KEM-%s", level)))
		sk := k.UnPackPrivateKey(skBytes)
		ss := k.Decapsulate(sk, ct)

		fmt.Println("✅ Kyber Decapsulation Successful")
		fmt.Printf("Shared Secret: %s\n", hex.EncodeToString(ss))
	},
}

func init() {
	// KeyGen flags
	kyberKeyGenCmd.Flags().String("z", "", "Z seed (hex)")
	kyberKeyGenCmd.Flags().String("d", "", "D seed (hex)")
	kyberKeyGenCmd.Flags().String("level", "512", "Security levels: 512, 768, 1024")

	// EnCaps flags
	kyberEncapsCmd.Flags().String("message", "", "Message (hex)")
	kyberEncapsCmd.Flags().String("pubKey", "", "Public key (hex)")
	kyberEncapsCmd.Flags().String("level", "512", "Security levels: 512, 768, 1024")

	// DeCaps flags
	kyberDecapsCmd.Flags().String("ciphertext", "", "Ciphertext (hex)")
	kyberDecapsCmd.Flags().String("privKey", "", "Private key (hex)")
	kyberDecapsCmd.Flags().String("level", "512", "Security levels: 512, 768, 1024")

	kyberCmd.AddCommand(kyberKeyGenCmd, kyberEncapsCmd, kyberDecapsCmd)
}
