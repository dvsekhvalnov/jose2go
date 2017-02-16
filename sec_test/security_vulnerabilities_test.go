package sec_test

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/dvsekhvalnov/jose2go"
	"github.com/dvsekhvalnov/jose2go/keys/ecc"
	. "gopkg.in/check.v1"
	"testing"
)

func Test(t *testing.T) { TestingT(t) }

type SecurityTestSuite struct{}

var _ = Suite(&SecurityTestSuite{})

func (s *SecurityTestSuite) Test_InvalidCurve(c *C) {
	// https://www.cs.bris.ac.uk/Research/CryptographySecurity/RWC/2017/nguyen.quan.pdf
	// Attack exploits some ECDH implementations which do not check
	// that ephemeral public key is on the private key's curve.

	//given
	//JWT encrypted with attacker private key, which is equals to (reciever_pk mod 113)
	attackMod113 := "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiZ1RsaTY1ZVRRN3otQmgxNDdmZjhLM203azJVaURpRzJMcFlrV0FhRkpDYyIsInkiOiJjTEFuakthNGJ6akQ3REpWUHdhOUVQclJ6TUc3ck9OZ3NpVUQta2YzMEZzIiwiY3J2IjoiUC0yNTYifX0.qGAdxtEnrV_3zbIxU2ZKrMWcejNltjA_dtefBFnRh9A2z9cNIqYRWg.pEA5kX304PMCOmFSKX_cEg.a9fwUrx2JXi1OnWEMOmZhXd94-bEGCH9xxRwqcGuG2AMo-AwHoljdsH5C_kcTqlXS5p51OB1tvgQcMwB5rpTxg.72CHiYFecyDvuUa43KKT6w"

	//JWT encrypted with attacker private key, which is equals to (reciever_pk mod 2447)
	attackMod2447 := "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiWE9YR1E5XzZRQ3ZCZzN1OHZDSS1VZEJ2SUNBRWNOTkJyZnFkN3RHN29RNCIsInkiOiJoUW9XTm90bk56S2x3aUNuZUprTElxRG5UTnc3SXNkQkM1M1ZVcVZqVkpjIiwiY3J2IjoiUC0yNTYifX0.UGb3hX3ePAvtFB9TCdWsNkFTv9QWxSr3MpYNiSBdW630uRXRBT3sxw.6VpU84oMob16DxOR98YTRw.y1UslvtkoWdl9HpugfP0rSAkTw1xhm_LbK1iRXzGdpYqNwIG5VU33UBpKAtKFBoA1Kk_sYtfnHYAvn-aes4FTg.UZPN8h7FcvA5MIOq-Pkj8A"

	//when
	test, _, err := jose.Decode(attackMod113, Ecc256())

	//then
	c.Assert(err, NotNil)
	fmt.Printf("\nerr= %v\n", err)
	c.Assert(test, Equals, "")

	//when
	test, _, err = jose.Decode(attackMod2447, Ecc256())

	//then
	c.Assert(err, NotNil)
	fmt.Printf("\nerr= %v\n", err)
	c.Assert(test, Equals, "")
}

func Ecc256() *ecdsa.PrivateKey {
	return ecc.NewPrivate([]byte{193, 227, 73, 203, 97, 236, 112, 36, 140, 232, 1, 3, 76, 56, 52, 225, 184, 142, 190, 17, 97, 203, 37, 175, 56, 116, 31, 120, 95, 207, 196, 196},
		[]byte{123, 201, 103, 8, 239, 128, 149, 43, 83, 248, 210, 85, 95, 231, 43, 132, 30, 208, 69, 136, 98, 139, 29, 55, 138, 89, 73, 57, 80, 14, 201, 201},
		[]byte{84, 73, 131, 102, 144, 215, 92, 175, 41, 240, 221, 2, 157, 219, 49, 179, 221, 184, 171, 169, 210, 213, 21, 197, 1, 36, 101, 232, 23, 212, 169, 220})
}
