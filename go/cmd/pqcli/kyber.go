package pqcli

import (
	"encoding/hex"
	"fmt"
	kem "github.com/Deeptiman/forgelattice/go/crypto/kem/kyber"
	"github.com/spf13/cobra"
	"strings"
)

var kyberCmd = &cobra.Command{
	Use:   "kyber",
	Short: "CRYSTALS-Kyber (ML-KEM) operations",
}

var kyberKeyGenCmd = &cobra.Command{
	Use:   "kyber_keygen",
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
	Use:   "kyber_encaps",
	Short: "Encapsulate (KEM Encaps)",
	Run: func(cmd *cobra.Command, args []string) {
		msgHex, _ := cmd.Flags().GetString("msgHex")
		pkHex, _ := cmd.Flags().GetString("pubkey")
		level, _ := cmd.Flags().GetString("level")

		if msgHex == "" {
			fmt.Println("Error: --msgHex is required")
			cmd.Usage()
			return
		}

		if pkHex == "" {
			fmt.Println("Error: --pubkey is required")
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
	Use:   "kyber_decaps",
	Short: "Decapsulate (Recover shared secret)",
	Run: func(cmd *cobra.Command, args []string) {
		ctHex, _ := cmd.Flags().GetString("ct")
		skHex, _ := cmd.Flags().GetString("privkey")
		level, _ := cmd.Flags().GetString("level")

		if ctHex == "" {
			fmt.Println("Error: --ct is required")
			cmd.Usage()
			return
		}

		if skHex == "" {
			fmt.Println("Error: --privkey is required")
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

		fmt.Println("ct=", ct)
		fmt.Println("skBytes=", skBytes)

		k := kem.WithFIPS203(kem.ToLevel(fmt.Sprintf("ML-KEM-%s", level)))
		sk := k.UnPackPrivateKey(skBytes)
		ss := k.Decapsulate(sk, ct)

		fmt.Println("✅ Kyber Decapsulation Successful")
		fmt.Printf("Shared Secret: %s\n", hex.EncodeToString(ss))
	},
}

func init() {
	// Keygen flags
	kyberKeyGenCmd.Flags().String("z", "", "Z seed (hex)")
	kyberKeyGenCmd.Flags().String("d", "", "D seed (hex)")
	kyberKeyGenCmd.Flags().String("level", "512", "Security level: 512, 768, 1024")

	// Encaps flags
	kyberEncapsCmd.Flags().String("msgHex", "", "Message (hex)")
	kyberEncapsCmd.Flags().String("pubkey", "", "Public key (hex)")
	kyberEncapsCmd.Flags().String("level", "512", "Security level: 512, 768, 1024")

	// Decaps flags
	kyberDecapsCmd.Flags().String("ct", "", "Ciphertext (hex)")
	kyberDecapsCmd.Flags().String("privkey", "", "Private key (hex)")
	kyberDecapsCmd.Flags().String("level", "512", "Security level: 512, 768, 1024")

	kyberCmd.AddCommand(kyberKeyGenCmd, kyberEncapsCmd, kyberDecapsCmd)
}
