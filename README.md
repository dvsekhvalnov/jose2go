# Golang (GO) Javascript Object Signing and Encryption (JOSE) and JSON Web Token (JWT) implementation

Pure Golang (GO) library for generating, decoding and encryption [JSON Web Tokens](http://tools.ietf.org/html/draft-jones-json-web-token-10). Supports some of [JSON Web Algorithms](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-23). 
Extensively tested for compatibility with [jose.4.j](https://bitbucket.org/b_c/jose4j/wiki/Home), [Nimbus-JOSE-JWT](https://bitbucket.org/nimbusds/nimbus-jose-jwt/wiki/Home), [json-jwt](https://github.com/nov/json-jwt) and
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
### Creating Plaintext (unprotected) Tokens	
	payload :=  `{"hello": "world"}`
			
	token,err := Sign(payload,"none",nil)
	
	if(err==nil) {
		//go use token
	}
		
### More examples
Checkout jose_test.go for more examples.	