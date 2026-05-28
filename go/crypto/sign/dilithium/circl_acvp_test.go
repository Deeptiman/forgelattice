package sign

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Deeptiman/forgelattice/go/crypto/sign/dilithium/internal/common"
	"github.com/Deeptiman/forgelattice/go/crypto/sign/dilithium/internal/dsa"
	"testing"
)

func TestACVP(t *testing.T) {
	for _, sub := range []string{
		"keyGen",
		"sigGen",
		"sigVer",
	} {
		t.Run(sub, func(t *testing.T) {
			testACVP(t, sub)
		})
	}
}

// nolint:funlen,gocyclo
func testACVP(t *testing.T, sub string) {
	buf, err := ReadGzip("./testdata/ML-DSA-" + sub + "-FIPS204/prompt.json.gz")
	if err != nil {
		t.Fatal(err)
	}

	var prompt struct {
		TestGroups []json.RawMessage `json:"testGroups"`
	}

	if err = json.Unmarshal(buf, &prompt); err != nil {
		t.Fatal(err)
	}

	buf, err = ReadGzip("./testdata/ML-DSA-" + sub + "-FIPS204/expectedResults.json.gz")
	if err != nil {
		t.Fatal(err)
	}

	var results struct {
		TestGroups []json.RawMessage `json:"testGroups"`
	}

	if err := json.Unmarshal(buf, &results); err != nil {
		t.Fatal(err)
	}

	rawResults := make(map[int]json.RawMessage)

	for _, rawGroup := range results.TestGroups {
		var abstractGroup struct {
			Tests []json.RawMessage `json:"tests"`
		}
		if err := json.Unmarshal(rawGroup, &abstractGroup); err != nil {
			t.Fatal(err)
		}
		for _, rawTest := range abstractGroup.Tests {
			var abstractTest struct {
				TcID int `json:"tcId"`
			}
			if err := json.Unmarshal(rawTest, &abstractTest); err != nil {
				t.Fatal(err)
			}
			if _, exists := rawResults[abstractTest.TcID]; exists {
				t.Fatalf("Duplicate test id: %d", abstractTest.TcID)
			}
			rawResults[abstractTest.TcID] = rawTest
		}
	}

	for _, scheme := range []API{
		WithFIPS204(dsa.Level2),
		WithFIPS204(dsa.Level3),
		WithFIPS204(dsa.Level5),
	} {
		t.Run(fmt.Sprintf("Scheme=%s", scheme.Scheme()), func(t *testing.T) {
			for _, rawGroup := range prompt.TestGroups {
				var abstractGroup struct {
					TestType string `json:"testType"`
				}
				if err := json.Unmarshal(rawGroup, &abstractGroup); err != nil {
					t.Fatal(err)
				}
				switch {
				case abstractGroup.TestType == "AFT" && sub == "keyGen":
					var group struct {
						TgID         int    `json:"tgId"`
						ParameterSet string `json:"parameterSet"`
						Tests        []struct {
							TcID int      `json:"tcId"`
							Seed HexBytes `json:"seed"`
						}
					}
					if err := json.Unmarshal(rawGroup, &group); err != nil {
						t.Fatal(err)
					}

					if group.ParameterSet != scheme.Scheme() {
						continue
					}

					for _, tst := range group.Tests {
						var result struct {
							Pk HexBytes `json:"pk"`
							Sk HexBytes `json:"sk"`
						}
						rawResult, ok := rawResults[tst.TcID]
						if !ok {
							t.Fatalf("Missing result: %d", tst.TcID)
						}
						if err := json.Unmarshal(rawResult, &result); err != nil {
							t.Fatal(err)
						}

						var seed2 [common.SeedSize]byte
						copy(seed2[:], tst.Seed)
						pk, sk := scheme.GenerateKeyPair(seed2)

						pk2 := scheme.UnmarshalPublicKey(result.Pk)
						sk2 := scheme.UnmarshalPrivateKey(result.Sk)

						if !scheme.IsPublicKeyValid(pk, pk2) {
							t.Fatal("pk does not match")
						}
						if !scheme.IsPrivateKeyValid(sk, sk2) {
							t.Fatal("sk does not match")
						}
					}
				case abstractGroup.TestType == "AFT" && sub == "sigGen":
					var group struct {
						TgID          int    `json:"tgId"`
						ParameterSet  string `json:"parameterSet"`
						Deterministic bool   `json:"deterministic"`
						Tests         []struct {
							TcID    int      `json:"tcId"`
							Sk      HexBytes `json:"sk"`
							Message HexBytes `json:"message"`
							Rnd     HexBytes `json:"rnd"`
						}
					}
					if err := json.Unmarshal(rawGroup, &group); err != nil {
						t.Fatal(err)
					}

					if group.ParameterSet != scheme.Scheme() {
						continue
					}

					for _, tst := range group.Tests {
						var result struct {
							Signature HexBytes `json:"signature"`
						}
						rawResult, ok := rawResults[tst.TcID]
						if !ok {
							t.Fatalf("Missing result: %d", tst.TcID)
						}
						if err := json.Unmarshal(rawResult, &result); err != nil {
							t.Fatal(err)
						}

						var rnd [32]byte
						if !group.Deterministic {
							copy(rnd[:], tst.Rnd)
						}
						sig2 := scheme.Sign(tst.Sk, tst.Message, rnd)
						if !bytes.Equal(sig2, result.Signature) {
							t.Fatalf("signature doesn't match: %x ≠ %x",
								sig2, result.Signature)
						}
					}
				case abstractGroup.TestType == "AFT" && sub == "sigVer":
					var group struct {
						TgID         int      `json:"tgId"`
						ParameterSet string   `json:"parameterSet"`
						Pk           HexBytes `json:"pk"`
						Tests        []struct {
							TcID      int      `json:"tcId"`
							Message   HexBytes `json:"message"`
							Signature HexBytes `json:"signature"`
						}
					}
					if err := json.Unmarshal(rawGroup, &group); err != nil {
						t.Fatal(err)
					}

					if group.ParameterSet != scheme.Scheme() {
						continue
					}

					for _, tst := range group.Tests {
						var result struct {
							TestPassed bool `json:"testPassed"`
						}
						rawResult, ok := rawResults[tst.TcID]
						if !ok {
							t.Fatalf("Missing result: %d", tst.TcID)
						}
						if err := json.Unmarshal(rawResult, &result); err != nil {
							t.Fatal(err)
						}
						passed2 := scheme.Verify(group.Pk, tst.Signature, tst.Message)
						if passed2 != result.TestPassed {
							t.Fatalf("verification %v ≠ %v", passed2, result.TestPassed)
						}
					}
				default:
					t.Fatalf("unknown type %s for %s", abstractGroup.TestType, sub)
				}
			}
		})
	}
}
