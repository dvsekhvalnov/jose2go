# Golang (GO) Javascript Object Signing and Encryption (JOSE) and JSON Web Token (JWT) implementation

Pure Golang (GO) library for generating, decoding and encryption [JSON Web Tokens](http://tools.ietf.org/html/draft-jones-json-web-token-10). Supports all signature algorithms and some key management of [JSON Web Algorithms](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-23). 
Extensively unit tested and cross tested for compatibility with [jose.4.j](https://bitbucket.org/b_c/jose4j/wiki/Home), [Nimbus-JOSE-JWT](https://bitbucket.org/nimbusds/nimbus-jose-jwt/wiki/Home), [json-jwt](https://github.com/nov/json-jwt) and
[jose-jwt](https://github.com/dvsekhvalnov/jose-jwt) libraries. 

## Goal
The project goal is to provide full suite of JOSE algorithms. Ideally relying only on standard Golang (GO) packages only.

##Status
In rather active development. API is not stable at the moment and can change in future versions.

## Supported JWA algorithms

**Signing**
- HMAC signatures with HS256, HS384 and HS512.
- RSASSA-PKCS1-V1_5 signatures with RS256, RS384 and RS512.
- RSASSA-PSS signatures (probabilistic signature scheme with appendix) with PS256, PS384 and PS512.
- ECDSA signatures with ES256, ES384 and ES512.
- NONE (unprotected) plain text algorithm without integrity protection

**Encryption**
- RSAES OAEP encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- RSAES-PKCS1-V1_5 encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- A128KW, A192KW, A256KW encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- A128GCMKW, A192GCMKW, A256GCMKW encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM
- Direct symmetric key encryption with pre-shared key A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM and A256GCM

## Installation
### Grab package from github
`go get github.com/dvsekhvalnov/jose2go` or `go get -u github.com/dvsekhvalnov/jose2go` to update to latest version

### Import package
	import (
		"github.com/dvsekhvalnov/jose2go"
	)

## Usage
#### Creating Plaintext (unprotected) Tokens	
	package main

	import (
		"fmt"
		"github.com/dvsekhvalnov/jose2go"
	)

	func main() {

		payload :=  `{"hello": "world"}`
	
		token,err := jose.Sign(payload,jose.NONE, nil)

		if(err==nil) {
			//go use token
			fmt.Printf("\nPlaintext = %v\n",token)
		}
	}

### Creating signed tokens
#### HS-256, HS-384 and HS-512
Signing with HS256, HS384, HS512 expecting `[]byte` array key of corresponding length:

	package main

	import (
		"fmt"
		"github.com/dvsekhvalnov/jose2go"
	)

	func main() {

		payload :=  `{"hello": "world"}`
	
		key := []byte{97,48,97,50,97,98,100,56,45,54,49,54,50,45,52,49,99,51,45,56,51,100,54,45,49,99,102,53,53,57,98,52,54,97,102,99}		
	
		token,err := jose.Sign(payload,jose.HS256,key)

		if(err==nil) {
			//go use token
			fmt.Printf("\nHS256 = %v\n",token)
		}
	}
	
#### RS-256, RS-384 and RS-512, PS-256, PS-384 and PS-512
Signing with RS256, RS384, RS512, PS256, PS384, PS512 expecting `*rsa.PrivateKey` private key of corresponding length. **jose2go** provides convinient utils to construct `*rsa.PrivateKey` instance from PEM encoded PKCS1 or PKCS8 data: `Rsa.ReadPrivate([]byte)` under `jose2go/keys/rsa` package.

	package main

	import (
		"fmt"
		"io/ioutil"
		"github.com/dvsekhvalnov/jose2go/keys/rsa"
		"github.com/dvsekhvalnov/jose2go"
	)

	func main() {

		payload :=  `{"hello": "world"}`

		keyBytes,err := ioutil.ReadFile("private.key")

		if(err!=nil) {
			panic("invalid key file")
		}

		privateKey,e:=Rsa.ReadPrivate(keyBytes)

		if(e!=nil) {
			panic("invalid key format")
		}
	
		token,err := jose.Sign(payload,jose.RS256, privateKey)

		if(err==nil) {
			//go use token
			fmt.Printf("\nRS256 = %v\n",token)
		}
	}	

#### ES-256, ES-384 and ES-512
ES256, ES384, ES512 ECDSA signatures expecting `*ecdsa.PrivateKey` private elliptic curve key of corresponding length.  **jose2go** provides convinient utils to construct `*ecdsa.PrivateKey` instance from PEM encoded PKCS1 or PKCS8 data: `ecc.ReadPrivate([]byte)` or directly from `X,Y,D` parameters: `ecc.NewPrivate(x,y,d []byte)` under `jose2go/keys/ecc` package.

	package main

	import (
	    "fmt"
	    "github.com/dvsekhvalnov/jose2go/keys/ecc"
	    "github.com/dvsekhvalnov/jose2go"
	)

	func main() {

	    payload := `{"hello":"world"}`

		privateKey:=ecc.NewPrivate([]byte{4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9},
		 			 			   []byte{131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53},
								   []byte{ 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 })
	
	    token,err := jose.Sign(payload, jose.ES256, privateKey)

	    if(err==nil) {
	        //go use token
	        fmt.Printf("\ntoken = %v\n",token)
	    }
	}  

### Creating encrypted Tokens
#### RSA-OAEP and RSA1\_5 key management algorithm
RSA-OAEP and RSA1_5 key management expecting `*rsa.PublicKey` public key of corresponding length.

	package main

	import (
	    "fmt"
		"io/ioutil"
	    "github.com/dvsekhvalnov/jose2go/keys/rsa"
	    "github.com/dvsekhvalnov/jose2go"
	)

	func main() {

		payload :=  `{"hello": "world"}`
	
		keyBytes,err := ioutil.ReadFile("public.key")

		if(err!=nil) {
			panic("invalid key file")
		}

		publicKey,e:=Rsa.ReadPublic(keyBytes)

		if(e!=nil) {
			panic("invalid key format")
		}

		//OR:
		//token,err := jose.Encrypt(payload, jose.RSA1_5, jose.A256GCM, publicKey)		
		token,err := jose.Encrypt(payload, jose.RSA_OAEP, jose.A256GCM, publicKey)

	    if(err==nil) {
	        //go use token
	        fmt.Printf("\ntoken = %v\n",token)
	    }
	}  
#### AES Key Wrap key management family of algorithms
AES128KW, AES192KW and AES256KW key management requires `[]byte` array key of corresponding length

	package main

	import (
		"fmt"
		"github.com/dvsekhvalnov/jose2go"
	)

	func main() {

		payload :=  `{"hello": "world"}`

		sharedKey :=[]byte{194,164,235,6,138,248,171,239,24,216,11,22,137,199,215,133}

		token,err := jose.Encrypt(payload,jose.A128KW,jose.A128GCM,sharedKey)

		if(err==nil) {
			//go use token
			fmt.Printf("\nA128KW A128GCM = %v\n",token)
		}
	}

#### AES GCM Key Wrap key management family of algorithms
AES128GCMKW, AES192GCMKW and AES256GCMKW key management requires `[]byte` array key of corresponding length

	package main

	import (
		"fmt"
		"github.com/dvsekhvalnov/jose2go"
	)

	func main() {

		payload :=  `{"hello": "world"}`

		sharedKey :=[]byte{194,164,235,6,138,248,171,239,24,216,11,22,137,199,215,133}

		token,err := jose.Encrypt(payload,jose.A128GCMKW,jose.A128GCM,sharedKey)

		if(err==nil) {
			//go use token
			fmt.Printf("\nA128GCMKW A128GCM = %v\n",token)
		}
	}

#### PBES2 using HMAC SHA with AES Key Wrap key management family of algorithms
PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW key management requires `string` passphrase from which actual key will be derived 

	package main

	import (
		"fmt"
		"github.com/dvsekhvalnov/jose2go"
	)

	func main() {

		payload :=  `{"hello": "world"}`

		passphrase := `top secret`

		token,err := jose.Encrypt(payload,jose.PBES2_HS256_A128KW,jose.A256GCM,passphrase)

		if(err==nil) {
			//go use token
			fmt.Printf("\nPBES2_HS256_A128KW A256GCM = %v\n",token)
		}
	}

#### DIR direct pre-shared symmetric key management
Direct key management with pre-shared symmetric keys expecting `[]byte` array key of corresponding length:

	package main

	import (
		"fmt"
		"github.com/dvsekhvalnov/jose2go"
	)

	func main() {

		payload :=  `{"hello": "world"}`
	
		sharedKey :=[]byte{194,164,235,6,138,248,171,239,24,216,11,22,137,199,215,133}
	
		token,err := jose.Encrypt(payload,jose.DIR,jose.A128GCM,sharedKey)

		if(err==nil) {
			//go use token
			fmt.Printf("\nDIR A128GCM = %v\n",token)
		}
	}
	
### Verifying and Decoding Tokens
Decoding json web tokens is fully symmetric to creating signed or encrypted tokens (with respect to public/private cryptography):		

**HS256, HS384, HS512** signatures, **A128KW, A192KW, A256KW**,**A128GCMKW, A192GCMKW, A256GCMKW** and **DIR** key management algorithm expecting `[]byte` array key:

	package main

	import (
		"fmt"
		"github.com/dvsekhvalnov/jose2go"
	)

	func main() {

		token := "eyJhbGciOiJIUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.chIoYWrQMA8XL5nFz6oLDJyvgHk2KA4BrFGrKymjC8E"
	
		sharedKey :=[]byte{97,48,97,50,97,98,100,56,45,54,49,54,50,45,52,49,99,51,45,56,51,100,54,45,49,99,102,53,53,57,98,52,54,97,102,99}
	
		payload,err := jose.Decode(token,sharedKey)

		if(err==nil) {
			//go use token
			fmt.Printf("\npayload = %v\n",payload)
		}
	}

**RS256, RS384, RS512**,**PS256, PS384, PS512** signatures expecting `*rsa.PublicKey` public key of corresponding length. **jose2go** provides convinient utils to construct `*rsa.PublicKey` instance from PEM encoded PKCS1 X509 certificate or PKIX data: `Rsa.ReadPublic([]byte)` under `jose2go/keys/rsa` package:

	package main

	import (
	    "fmt"
	    "io/ioutil"
	    "github.com/dvsekhvalnov/jose2go/keys/rsa"
	    "github.com/dvsekhvalnov/jose2go"
	)

	func main() {

	    token := "eyJhbGciOiJSUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.NL_dfVpZkhNn4bZpCyMq5TmnXbT4yiyecuB6Kax_lV8Yq2dG8wLfea-T4UKnrjLOwxlbwLwuKzffWcnWv3LVAWfeBxhGTa0c4_0TX_wzLnsgLuU6s9M2GBkAIuSMHY6UTFumJlEeRBeiqZNrlqvmAzQ9ppJHfWWkW4stcgLCLMAZbTqvRSppC1SMxnvPXnZSWn_Fk_q3oGKWw6Nf0-j-aOhK0S0Lcr0PV69ZE4xBYM9PUS1MpMe2zF5J3Tqlc1VBcJ94fjDj1F7y8twmMT3H1PI9RozO-21R0SiXZ_a93fxhE_l_dj5drgOek7jUN9uBDjkXUwJPAyp9YPehrjyLdw"

	    keyBytes,err := ioutil.ReadFile("public.key")

	    if(err!=nil) {
	        panic("invalid key file")
	    }

	    publicKey,e:=Rsa.ReadPublic(keyBytes)

	    if(e!=nil) {
	        panic("invalid key format")
	    }
	
	    payload,err := jose.Decode(token, publicKey)

	    if(err==nil) {
	        //go use token
	        fmt.Printf("\npayload = %v\n",payload)
	    }
	}  

**RSA-OAEP** and **RSA1_5** key management algorithms expecting `*rsa.PrivateKey` private key of corresponding length:

	package main

	import (
	    "fmt"
	    "io/ioutil"
	    "github.com/dvsekhvalnov/jose2go/keys/rsa"
	    "github.com/dvsekhvalnov/jose2go"
	)

	func main() {

	    token := "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2R0NNIn0.ixD3WVOkvaxeLKi0kyVqTzM6W2EW25SHHYCAr9473Xq528xSK0AVux6kUtv7QMkQKgkMvO8X4VdvonyGkDZTK2jgYUiI06dz7I1sjWJIbyNVrANbBsmBiwikwB-9DLEaKuM85Lwu6gnzbOF6B9R0428ckxmITCPDrzMaXwYZHh46FiSg9djChUTex0pHGhNDiEIgaINpsmqsOFX1L2Y7KM2ZR7wtpR3kidMV3JlxHdKheiPKnDx_eNcdoE-eogPbRGFdkhEE8Dyass1ZSxt4fP27NwsIer5pc0b922_3XWdi1r1TL_fLvGktHLvt6HK6IruXFHpU4x5Z2gTXWxEIog.zzTNmovBowdX2_hi.QSPSgXn0w25ugvzmu2TnhePn.0I3B9BE064HFNP2E0I7M9g"

	    keyBytes,err := ioutil.ReadFile("private.key")

	    if(err!=nil) {
	        panic("invalid key file")
	    }

	    privateKey,e:=Rsa.ReadPrivate(keyBytes)

	    if(e!=nil) {
	        panic("invalid key format")
	    }

	    payload,err := jose.Decode(token, privateKey)

	    if(err==nil) {
	        //go use payload
	        fmt.Printf("\npayload = %v\n",payload)
	    }
	}  

**PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW** key management algorithms expects `string` passpharase as a key

	package main

	import (
		"fmt"
		"github.com/dvsekhvalnov/jose2go"
	)

	func main() {

		token :=  `eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjo4MTkyLCJwMnMiOiJlZWpFZTF0YmJVbU5XV2s2In0.J2HTgltxH3p7A2zDgQWpZPgA2CHTSnDmMhlZWeSOMoZ0YvhphCeg-w.FzYG5AOptknu7jsG.L8jAxfxZhDNIqb0T96YWoznQ.yNeOfQWUbm8KuDGZ_5lL_g`

		passphrase := `top secret`

		payload,err := jose.Decode(token,passphrase)

		if(err==nil) {
			//go use token
			fmt.Printf("\npayload = %v\n",payload)
		}
	}

**ES256, ES284, ES512** signatures expecting `*ecdsa.PublicKey` public elliptic curve key of corresponding length. **jose2go** provides convinient utils to construct `*ecdsa.PublicKey` instance from PEM encoded PKCS1 X509 certificate or PKIX data: `ecc.ReadPublic([]byte)` or directly from `X,Y` parameters: `ecc.NewPublic(x,y []byte)`under `jose2go/keys/ecc` package:

	package main

	import (
	    "fmt"
	    "github.com/dvsekhvalnov/jose2go/keys/ecc"
	    "github.com/dvsekhvalnov/jose2go"
	)

	func main() {

	    token := "eyJhbGciOiJFUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.EVnmDMlz-oi05AQzts-R3aqWvaBlwVZddWkmaaHyMx5Phb2NSLgyI0kccpgjjAyo1S5KCB3LIMPfmxCX_obMKA"

		publicKey:=ecc.NewPublic([]byte{4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9},
		 			 			 []byte{131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53})
	
	    payload,err := jose.Decode(token, publicKey)

	    if(err==nil) {
	        //go use token
	        fmt.Printf("\npayload = %v\n",payload)
	    }
	}
	
### More examples
Checkout `jose_test.go` for more examples.	