package cpapke

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestKyberParams(t *testing.T) {
	testCases := []struct {
		Level Level
		P     Constants
	}{
		{
			Level: Level512,
			P: Constants{
				K:              2,
				Eta1:           3,
				Eta2:           2,
				Du:             10,
				Dv:             4,
				CiphertextSize: 768,
				PublicKeySize:  800,
				PrivateKeySize: 768,
			},
		},
		{
			Level: Level768,
			P: Constants{
				K:              3,
				Eta1:           2,
				Eta2:           2,
				Du:             10,
				Dv:             4,
				CiphertextSize: 1088,
				PublicKeySize:  1184,
				PrivateKeySize: 1152,
			},
		},
		{
			Level: Level1024,
			P: Constants{
				K:              4,
				Eta1:           2,
				Eta2:           2,
				Du:             11,
				Dv:             5,
				CiphertextSize: 1568,
				PublicKeySize:  1568,
				PrivateKeySize: 1536,
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("Param-Test=%s", testCase.Level.String()), func(t *testing.T) {
			assert.Equal(t, testCase.P.K, ParamsFor(testCase.Level).K)
			assert.Equal(t, testCase.P.Eta1, ParamsFor(testCase.Level).Eta1)
			assert.Equal(t, testCase.P.Eta2, ParamsFor(testCase.Level).Eta2)
			assert.Equal(t, testCase.P.Du, ParamsFor(testCase.Level).Du)
			assert.Equal(t, testCase.P.Dv, ParamsFor(testCase.Level).Dv)
			assert.Equal(t, testCase.P.CiphertextSize, ParamsFor(testCase.Level).CiphertextSize)
			assert.Equal(t, testCase.P.PublicKeySize, ParamsFor(testCase.Level).PublicKeySize)
			assert.Equal(t, testCase.P.PrivateKeySize, ParamsFor(testCase.Level).PrivateKeySize)
		})
	}
}
