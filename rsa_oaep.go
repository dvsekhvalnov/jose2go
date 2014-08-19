package jose

import (
	"errors"
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha1"
	"jose2go/arrays"
)

func init() {
	RegisterJwa(new(RsaOaep))
}

type RsaOaep struct{
}

func (alg *RsaOaep) Name() string {
	return RSA_OAEP
}

func (alg *RsaOaep) WrapNewKey(cekSizeBits int, key interface{}, header map[string]interface{}) (cek []byte, encryptedCek []byte, err error) {
	if pubKey,ok:=key.(*rsa.PublicKey);ok {
		if cek,err = arrays.Random(cekSizeBits>>3);err==nil {			
			encryptedCek,err=rsa.EncryptOAEP(sha1.New(),rand.Reader,pubKey,cek,nil)
			return
		}

		return nil,nil,err
	}

	return nil,nil,errors.New("RsaOaep.WrapNewKey(): expected key to be '*rsa.PublicKey'")

}

func (alg *RsaOaep) Unwrap(encryptedCek []byte, key interface{}, cekSizeBits int, header map[string]interface{}) (cek []byte, err error) {
	if privKey,ok:=key.(*rsa.PrivateKey);ok {
		return rsa.DecryptOAEP(sha1.New(), rand.Reader, privKey, encryptedCek, nil)
	}
	
	return nil,errors.New("RsaOaep.Unwrap(): expected key to be '*rsa.PrivateKey'")		
}
