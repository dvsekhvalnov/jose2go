# Golang (GO) Javascript Object Signing and Encryption (JOSE) and JSON Web Token (JWT) implementation

Pure Golang (GO) library for generating, decoding and encryption [JSON Web Tokens](http://tools.ietf.org/html/draft-jones-json-web-token-10). Supports some of [JSON Web Algorithms](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-23). 
Extensively unit tested and cross tested for compatibility with [jose.4.j](https://bitbucket.org/b_c/jose4j/wiki/Home), [Nimbus-JOSE-JWT](https://bitbucket.org/nimbusds/nimbus-jose-jwt/wiki/Home), [json-jwt](https://github.com/nov/json-jwt) and
[jose-jwt](https://github.com/dvsekhvalnov/jose-jwt) libraries. 

## Goal
The project goal is to provide full suite of JOSE algorithms. Ideally relying only on standard Golang (GO) package.

##Status
In rather active development. API is not stable at the moment and can change in future versions.

## Supported JWA algorithms

**Signing**
- HMAC signatures with HS256, HS384 and HS512.
- RSASSA-PKCS1-V1_5 signatures with RS256, RS384 and RS512.
- NONE (unprotected) plain text algorithm without integrity protection

**Encryption**
- Direct symmetric key encryption with pre-shared key A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM and A256GCM

## Installation
### Grab package from github
`go get github.com/dvsekhvalnov/jose2go`

### Import package
`import (
	"github.com/dvsekhvalnov/jose2go"
)`

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
	
#### RS-256, RS-384 and RS-512	
Signing with RS256, RS384, RS512 expecting `*rsa.PrivateKey` private key of corresponding length. **jose2go** provides convinient utils to construct `*rsa.PrivateKey` instance from PEM encoded PKCS1 or PKCS8 data: `Rsa.NewPrivate([]byte)` under `jose2go/keys/rsa` package.

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

		privateKey,e:=Rsa.NewPrivate(keyBytes)

		if(e!=nil) {
			panic("invalid key format")
		}
	
		token,err := jose.Sign(payload,jose.RS256, privateKey)

		if(err==nil) {
			//go use token
			fmt.Printf("\nRS256 = %v\n",token)
		}
	}	

### Creating encrypted Tokens
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

**HS256, HS384, HS512** signatures expecting `[]byte` array key:

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

### More examples
Checkout `jose_test.go` for more examples.	