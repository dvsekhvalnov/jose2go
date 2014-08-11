package jose

type Plaintext struct{}

func init() {
	RegisterJws(new(Plaintext))
}

func (alg *Plaintext) Name() string {
	return "none"
}

func (alg *Plaintext) Verify(securedInput []byte, signature []byte, key interface{}) error {
	return nil
}

func (alg *Plaintext) Sign(securedInput []byte, key interface{}) (signature []byte, err error) {
	return []byte{},nil
}
