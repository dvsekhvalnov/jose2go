package sec_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	jose "github.com/dvsekhvalnov/jose2go"
	"github.com/dvsekhvalnov/jose2go/arrays"
	"github.com/dvsekhvalnov/jose2go/keys/ecc"
	Rsa "github.com/dvsekhvalnov/jose2go/keys/rsa"
	. "gopkg.in/check.v1"
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

func (s *SecurityTestSuite) Test_AAD_IntegerOverflow(c *C) {
	//Borrowed test case from https://bitbucket.org/b_c/jose4j/commits/b79e67c13c23

	cek := []byte{57, 188, 52, 101, 199, 208, 135, 76, 159, 67, 65, 71, 196, 136, 137, 113, 227, 232, 28, 1, 61, 157, 73, 156, 68, 103, 67, 250, 215, 162, 181, 161}

	aad := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	plainText := make([]byte, 536870928, 536870928)

	//generate random plaintext
	for i := 0; i < len(plainText); i += 8 {
		bytes := arrays.UInt64ToBytes(uint64(i))
		plainText[i] = bytes[0]
		plainText[i+1] = bytes[1]
		plainText[i+2] = bytes[2]
		plainText[i+3] = bytes[3]
		plainText[i+4] = bytes[4]
		plainText[i+5] = bytes[5]
		plainText[i+6] = bytes[6]
		plainText[i+7] = bytes[7]
	}

	enc := &jose.AesCbcHmac{}
	enc.SetKeySizeBits(256)

	iv, cipherText, authTag, _ := enc.Encrypt(aad, plainText, cek)

	// Now shift aad and ciphertext around so that HMAC doesn't change,
	// but the plaintext will change.

	buffer := arrays.Concat(aad, iv, cipherText)

	// Note that due to integer overflow 536870920 * 8 = 64
	newAadSize := 536870920

	newAad := buffer[0:newAadSize]
	newIv := buffer[newAadSize : newAadSize+16]
	newCipherText := buffer[newAadSize+16:]

	//decrypt shifted binary, it should fail, since content is different now
	test, err := enc.Decrypt(newAad, cek, newIv, newCipherText, authTag)

	//if we reach that point HMAC check was bypassed although the decrypted data is different

	c.Assert(err, NotNil)
	fmt.Printf("\nerr= %v\n", err)
	c.Assert(test, IsNil)
}

func (s *SecurityTestSuite) Test_DeflateBomb(c *C) {
	strU := strings.Repeat("U", 400000000)
	strUU := strings.Repeat("U", 100000000)

	payloadMap := map[string]string{
		"U":  strU,
		"UU": strUU,
	}

	payloadBytes, _ := json.Marshal(payloadMap)

	fmt.Println("Uncompressed payload length", len(payloadBytes))
	test, _ := jose.Encrypt(string(payloadBytes), jose.RSA_OAEP, jose.A256GCM, PubKey(), jose.Zip(jose.DEF))
	fmt.Println("Encoded & Compressed token length", len(test))

	start := time.Now()
	payload, headers, err := jose.Decode(test, PrivKey())
	timeElapsed := time.Since(start)
	fmt.Printf("The `decode` took %s\n", timeElapsed)

	c.Assert(payload, Equals, "")
	c.Assert(headers, IsNil)
	c.Assert(err, Equals, jose.ErrSizeExceeded)
}

func Ecc256() *ecdsa.PrivateKey {
	return ecc.NewPrivate([]byte{193, 227, 73, 203, 97, 236, 112, 36, 140, 232, 1, 3, 76, 56, 52, 225, 184, 142, 190, 17, 97, 203, 37, 175, 56, 116, 31, 120, 95, 207, 196, 196},
		[]byte{123, 201, 103, 8, 239, 128, 149, 43, 83, 248, 210, 85, 95, 231, 43, 132, 30, 208, 69, 136, 98, 139, 29, 55, 138, 89, 73, 57, 80, 14, 201, 201},
		[]byte{84, 73, 131, 102, 144, 215, 92, 175, 41, 240, 221, 2, 157, 219, 49, 179, 221, 184, 171, 169, 210, 213, 21, 197, 1, 36, 101, 232, 23, 212, 169, 220})
}

func PubKey() *rsa.PublicKey {
	key, _ := Rsa.ReadPublic([]byte(pubKey))
	return key
}

func PrivKey() *rsa.PrivateKey {
	key, _ := Rsa.ReadPrivate([]byte(privKey))
	return key
}

var pubKey = `-----BEGIN CERTIFICATE-----
MIICnTCCAYUCBEReYeAwDQYJKoZIhvcNAQEFBQAwEzERMA8GA1UEAxMIand0LTIw
NDgwHhcNMTQwMTI0MTMwOTE2WhcNMzQwMjIzMjAwMDAwWjATMREwDwYDVQQDEwhq
d3QtMjA0ODCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKhWb9KXmv45
+TKOKhFJkrboZbpbKPJ9Yp12xKLXf8060KfStEStIX+7dCuAYylYWoqiGpuLVVUL
5JmHgXmK9TJpzv9Dfe3TAc/+35r8r9IYB2gXUOZkebty05R6PLY0RO/hs2ZhrOoz
HMo+x216Gwz0CWaajcuiY5Yg1V8VvJ1iQ3rcRgZapk49RNX69kQrGS63gzj0gyHn
Rtbqc/Ua2kobCA83nnznCom3AGinnlSN65AFPP5jmri0l79+4ZZNIerErSW96mUF
8jlJFZI1yJIbzbv73tL+y4i0+BvzsWBs6TkHAp4pinaI8zT+hrVQ2jD4fkJEiRN9
lAqLPUd8CNkCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAnqBw3UHOSSHtU7yMi1+H
E+9119tMh7X/fCpcpOnjYmhW8uy9SiPBZBl1z6vQYkMPcURnDMGHdA31kPKICZ6G
LWGkBLY3BfIQi064e8vWHW7zX6+2Wi1zFWdJlmgQzBhbr8pYh9xjZe6FjPwbSEuS
0uE8dWSWHJLdWsA4xNX9k3pr601R2vPVFCDKs3K1a8P/Xi59kYmKMjaX6vYT879y
gWt43yhtGTF48y85+eqLdFRFANTbBFSzdRlPQUYa5d9PZGxeBTcg7UBkK/G+d6D5
sd78T2ymwlLYrNi+cSDYD6S4hwZaLeEK6h7p/OoG02RBNuT4VqFRu5DJ6Po+C6Jh
qQ==
-----END CERTIFICATE-----`

var privKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqFZv0pea/jn5Mo4qEUmStuhlulso8n1inXbEotd/zTrQp9K0
RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO/0N97dMBz/7fmvyv0hgHaBdQ
5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxG
BlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8
/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu/ve0v7LiLT4G/OxYGzpOQcC
nimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI2QIDAQABAoIBAQCUmHBvSkqUHaK/
IMU7q2FqOi0KWswDefEiJKQhRu9Wv5NOgW2FrfqDIXrDp7pg1dBezgeExHLX9v6d
FAOTwbj9/m6t3+r6k6fm7gp+ao3dfD6VgPd12L2oXQ0t5NVQ1UUBJ4/QUWps9h90
3AP4vK/COG1P+CAw4DDeZi9TlwF/Pr7e492GXcLBAUJODA6538ED2nYw8xQcbzbA
wr+w07UjRNimObtOfA0HCIpsx/6LkIqe6iGChisQNgt4yDd/fZ4GWOUIU1hqgK1P
6avVl7Q5Mk0PTi9t8ui1X4EEq6Uils45J5WkobuAnFkea/uKfs8Tn9bNrEoVWgdb
fBHq/8bNAoGBANKmjpE9e+L0RtxP+u4FN5YDoKE+i96VR7ru8H6yBKMcnD2uf5mV
RueEoL0FKHxlGBBo0dJWr1AIwpcPbTs3Dgx1/EQMZLg57QBZ7QcYETPiMwMvEM3k
Zf3G4YFYwUwIQXMYPt1ckr+RncRcq0GiKPDsvzzyNS+BBSmR5onAXd7bAoGBAMyT
6ggyqmiR/UwBn87em+GjbfX6YqxHHaQBdWwnnRX0JlGTNCxt6zLTgCIYxF4AA7eR
gfGTStwUJfAScjJirOe6Cpm1XDgxEQrT6oxAl17MR/ms/Z88WrT73G+4phVvDpVr
JcK+CCESnRI8xGLOLMkCc+5NpLajqWCOf1H2J8NbAoGAKTWmTGmf092AA1euOmRQ
5IsfIIxQ5qGDn+FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz+50xIDbs4/j5pWx1B
JVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW+/Iw4gKWN
ptxZ6T1lBD8UWHaPiEFW2+MCgYAmfSWoyS96YQ0QwbV5TDRzrTXA84yg8PhIpOWc
pY9OVBLpghJs0XlQpK4UvCglr0cDwGJ8OsP4x+mjUzUc+aeiKURZSt/Ayqp0KQ6V
uIlCEpjwBnXpAYfnSQNeGZVVrwFFZ1VBYFNTNZdLmRcxp6yRXN7G1ODKY9w4CFc3
6mHsxQKBgQCxEA+KAmmXxL++x/XOElOscz3vFHC4HbpHpOb4nywpE9vunnHE2WY4
EEW9aZbF22jx0ESU2XJ1JlqffvfIEvHNb5tmBWn4HZEpPUHdaFNhb9WjkMuFaLzh
cydwnEftq+3G0X3KSxp4p7R7afcnpNNqfneYODgoXxTQ4Q7ZyKo72A==
-----END RSA PRIVATE KEY-----`
