package jose

import (
	"jose2go/compact"
	"fmt"
	"errors"
	"encoding/json"
)

const (
	NONE="none"   //plaintext (unprotected) without signature / encryption
	
	HS256="HS256" //HMAC using SHA-256 hash
	HS384="HS384" //HMAC using SHA-384 hash
	HS512="HS512" //HMAC using SHA-512 hash
	RS256="RS256" //RSASSA-PKCS-v1_5 using SHA-256 hash 
	RS384="RS384" //RSASSA-PKCS-v1_5 using SHA-384 hash
	RS512="RS512" //RSASSA-PKCS-v1_5 using SHA-512 hash		
	PS256="PS256" //RSASSA-PSS using SHA-256 hash
	PS384="PS384" //RSASSA-PSS using SHA-384 hash
	PS512="PS512" //RSASSA-PSS using SHA-512 hash	
	ES256="ES256" //ECDSA using P-256 curve and SHA-256 hash
	ES384="ES384" //ECDSA using P-384 curve and SHA-384 hash
	ES512="ES512" //ECDSA using P-521 curve and SHA-512 hash		
	
	A128CBC_HS256="A128CBC-HS256" //AES in CBC mode with PKCS #5 (NIST.800-38A) padding with HMAC using 256 bit key
	A192CBC_HS384="A192CBC-HS384" //AES in CBC mode with PKCS #5 (NIST.800-38A) padding with HMAC using 384 bit key
	A256CBC_HS512="A256CBC-HS512" //AES in CBC mode with PKCS #5 (NIST.800-38A) padding with HMAC using 512 bit key
	A128GCM="A128GCM" //AES in GCM mode with 128 bit key
	A192GCM="A192GCM" //AES in GCM mode with 192 bit key
	A256GCM="A256GCM" //AES in GCM mode with 256 bit key
	
	DIR="dir"                 //Direct use of pre-shared symmetric key
	RSA1_5="RSA1_5"           //RSAES with PKCS #1 v1.5 padding, RFC 3447
	RSA_OAEP="RSA-OAEP"       //RSAES using Optimal Assymetric Encryption Padding, RFC 3447
    A128KW="A128KW"           //AES Key Wrap Algorithm using 128 bit keys, RFC 3394
    A192KW="A192KW"           //AES Key Wrap Algorithm using 192 bit keys, RFC 3394
    A256KW="A256KW"           //AES Key Wrap Algorithm using 256 bit keys, RFC 3394	
    A128GCMKW="A128GCMKW"     //AES GCM Key Wrap Algorithm using 128 bit keys
    A192GCMKW="A192GCMKW"     //AES GCM Key Wrap Algorithm using 192 bit keys
    A256GCMKW="A256GCMKW"     //AES GCM Key Wrap Algorithm using 256 bit keys
    PBES2_HS256_A128KW="PBES2-HS256+A128KW"    //Password Based Encryption using PBES2 schemes with HMAC-SHA and AES Key Wrap using 128 bit key
    PBES2_HS384_A192KW="PBES2-HS384+A192KW"    //Password Based Encryption using PBES2 schemes with HMAC-SHA and AES Key Wrap using 192 bit key
    PBES2_HS512_A256KW="PBES2-HS512+A256KW"    //Password Based Encryption using PBES2 schemes with HMAC-SHA and AES Key Wrap using 256 bit key
)

var jwsHashers = map[string]JwsAlgorithm{}
var jweEncryptors = map[string]JweEncryption{}
var jwaAlgorithms = map[string]JwaAlgorithm{}

func RegisterJwe(alg JweEncryption) {
	jweEncryptors[alg.Name()]=alg	
}

func RegisterJwa(alg JwaAlgorithm) {
	jwaAlgorithms[alg.Name()]=alg
}

func RegisterJws(alg JwsAlgorithm) {
	jwsHashers[alg.Name()]=alg
}

type JweEncryption interface {
	Encrypt(aad, plainText, cek []byte) (iv, cipherText, authTag []byte, err error)
	Decrypt(aad, cek, iv, cipherText, authTag []byte) (plainText []byte, err error)
	KeySizeBits() int
	Name() string	
}

type JwaAlgorithm interface {
	WrapNewKey(cekSizeBits int, key interface{}, header map[string]interface{}) (cek []byte, encryptedCek []byte, err error)
	Unwrap(encryptedCek []byte, key interface{}, cekSizeBits int, header map[string]interface{}) (cek []byte, err error)
	Name() string	
}

type JwsAlgorithm interface {
	Verify(securedInput, signature []byte, key interface{}) error
	Sign(securedInput []byte, key interface{}) (signature []byte, err error)
	Name() string
}

func Sign(payload string, signingAlg string, key interface{}) (token string, err error) { 
	if signer, ok := jwsHashers[signingAlg]; ok {
		
		jwtHeader := map[string]interface{} {
			"typ": "JWT",
			"alg": signingAlg,
		}
		
		paloadBytes := []byte(payload)	
		var header []byte
		var signature []byte		
	
		if header, err=json.Marshal(jwtHeader);err==nil {			
			securedInput := []byte(compact.Serialize(header, paloadBytes))
			
			if signature, err=signer.Sign(securedInput,key);err==nil {
				return compact.Serialize(header,paloadBytes,signature),nil			
			}			
		}
		
		return "",err	
	}
	
	return "",errors.New(fmt.Sprintf("jwt.Sign(): unknown algorithm: '%v'",signingAlg))
}

func Encrypt(payload string, alg string, enc string, key interface{}) (token string, err error) {
	
	var ok bool
	var keyMgmtAlg JwaAlgorithm
	var encAlg JweEncryption

	if keyMgmtAlg, ok=jwaAlgorithms[alg];!ok {
		return "",errors.New(fmt.Sprintf("jwt.Encrypt(): Unknown key management algorithm '%v'",alg))
	}

	if encAlg, ok=jweEncryptors[enc];!ok {
		return "",errors.New(fmt.Sprintf("jwt.Encrypt(): Unknown encryption algorithm '%v'",enc))
	}

	jwtHeader := map[string]interface{} {
		"enc": enc,
		"alg": alg,
	}

	var cek,encryptedCek,header,iv,cipherText,authTag []byte

	if cek,encryptedCek,err=keyMgmtAlg.WrapNewKey(encAlg.KeySizeBits(), key, jwtHeader);err!=nil {
		return "",err
	}
	
	if header, err=json.Marshal(jwtHeader);err!=nil {
		return "",err
	}			

    if iv, cipherText, authTag, err=encAlg.Encrypt([]byte(compact.Serialize(header)), []byte(payload), cek);err!=nil {
		return "",err
    }
	
	return compact.Serialize(header,encryptedCek,iv,cipherText,authTag),nil
}

func Decode(token string, key interface{}) (string,error) {
		
	parts:=compact.Parse(token)
	
	if(len(parts)==3) {
		return verify(parts,key)
	}
	
	if (len(parts)==5) {
		return decrypt(parts,key)
	}
	
	return "",errors.New(fmt.Sprintf("jwt.Decode() expects token of 3 or 5 parts, but was given: %v parts",len(parts)))	
}

func verify(parts [][]byte, key interface{}) (plainText string,err error) {
		
	header,payload,signature := parts[0],parts[1],parts[2]	
	
	secured := []byte(compact.Serialize(header,payload)) 
	
	var jwtHeader map[string]interface{}
	
	if err=json.Unmarshal(header,&jwtHeader);err!=nil {
		return "",err
	}
	
	alg := jwtHeader["alg"].(string)
	
	if verifier, ok := jwsHashers[alg]; ok {
		if err = verifier.Verify(secured,signature,key); err==nil {
				return string(payload),nil
		}
		
		return "", err
	}
	
	return "", errors.New(fmt.Sprintf("jwt.Decode(): Unknown algorithm: '%v'",alg))
}

func decrypt(parts [][]byte, key interface{}) (plainText string, err error) {
	
    header,encryptedCek,iv,cipherText,authTag := parts[0],parts[1],parts[2],parts[3],parts[4]
	
	var jwtHeader map[string]interface{}
	
	if e:=json.Unmarshal(header,&jwtHeader);e!=nil {
		return "",e 
	}
	
	alg := jwtHeader["alg"].(string)
	enc := jwtHeader["enc"].(string)	

	aad :=[]byte(compact.Serialize(header))
		
	var keyMgmtAlg JwaAlgorithm
	var encAlg JweEncryption
	var cek,plainBytes []byte
	var ok bool
	
	if keyMgmtAlg, ok = jwaAlgorithms[alg]; ok {
		if encAlg, ok = jweEncryptors[enc]; ok {
		    if cek,err=keyMgmtAlg.Unwrap(encryptedCek, key, encAlg.KeySizeBits(), jwtHeader);err==nil {
				if plainBytes,err = encAlg.Decrypt(aad, cek, iv, cipherText, authTag);err==nil {	
					return string(plainBytes),nil
				}
				
				return "",err
			}
			
			return "",err
		}
		
		return "",errors.New(fmt.Sprintf("jwt.decrypt(): Unknown encryption algorithm '%v'",enc))
	}
	
	return "",errors.New(fmt.Sprintf("jwt.decrypt(): Unknown key management algorithm '%v'",alg))
}
