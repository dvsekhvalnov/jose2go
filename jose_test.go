package jose

import (
	"crypto/rsa"
	"testing"
	"fmt"
	"strings"
	"jose2go/keys/rsa"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }
type TestSuite struct{}
var _ = Suite(&TestSuite{})

var shaKey=[]byte{97,48,97,50,97,98,100,56,45,54,49,54,50,45,52,49,99,51,45,56,51,100,54,45,49,99,102,53,53,57,98,52,54,97,102,99}
var aes128Key=[]byte{194,164,235,6,138,248,171,239,24,216,11,22,137,199,215,133}
var aes192Key=[]byte{139, 156, 136, 148, 17, 147, 27, 233, 145, 80, 115, 197, 223, 11, 100, 221, 5, 50, 155, 226, 136, 222, 216, 14}
var aes256Key=[]byte{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234}
var aes384Key = []byte{ 185, 30, 233, 199, 32, 98, 209, 3, 114, 250, 30, 124, 207, 173, 227, 152, 243, 202, 238, 165, 227, 199, 202, 230, 218, 185, 216, 113, 13, 53, 40, 100, 100, 20, 59, 67, 88, 97, 191, 3, 161, 37, 147, 223, 149, 237, 190, 156}
var aes512Key = []byte{ 238, 71, 183, 66, 57, 207, 194, 93, 82, 80, 80, 152, 92, 242, 84, 206, 194, 46, 67, 43, 231, 118, 208, 168, 156, 212, 33, 105, 27, 45, 60, 160, 232, 63, 61, 235, 68, 171, 206, 35, 152, 11, 142, 121, 174, 165, 140, 11, 172, 212, 13, 101, 13, 190, 82, 244, 109, 113, 70, 150, 251, 82, 215, 226 }

var pubKey=`-----BEGIN CERTIFICATE-----
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

var privKey=`-----BEGIN RSA PRIVATE KEY-----
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

func (s *TestSuite) TestDecodePlaintext(c *C) {
	//given
	token := "eyJhbGciOiJub25lIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9."
	
	//when	
	test,err := Decode(token,nil)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, `{"hello": "world"}`)
}

func (s *TestSuite) TestDecodeHS256(c *C) {
	//given
	token := "eyJhbGciOiJIUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.chIoYWrQMA8XL5nFz6oLDJyvgHk2KA4BrFGrKymjC8E"
	
	//when	
	test,err := Decode(token,shaKey)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, `{"hello": "world"}`)
}


func (s *TestSuite) TestDecodeHS384(c *C) {
	//given
	token := "eyJhbGciOiJIUzM4NCIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.McDgk0h4mRdhPM0yDUtFG_omRUwwqVS2_679Yeivj-a7l6bHs_ahWiKl1KoX_hU_"
	
	//when	
	test,err := Decode(token,shaKey)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, `{"hello": "world"}`)
}

func (s *TestSuite) TestDecodeHS512(c *C) {
	//given
	token := "eyJhbGciOiJIUzUxMiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.9KirTNe8IRwFCBLjO8BZuXf3U2ZVagdsg7F9ZsvMwG3FuqY9W0vqwjzPOjLqPN-GkjPm6C3qWPnINhpr5bEDJQ"
	
	//when	
	test,err := Decode(token,shaKey)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, `{"hello": "world"}`)
}

func (s *TestSuite) TestEncodePlaintext(c *C) {
	//given
	payload :=  `{"hello": "world"}`
	
	//when	
	test,err := Sign(payload,NONE,nil)
	
	fmt.Printf("\nnone = %v\n",test)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.")	
	
	//make sure we consistent with outselfs
	t,_:=Decode(test,shaKey)
	c.Assert(t, Equals, payload) 
}

func (s *TestSuite) TestEncodeHS256(c *C) {
	//given
	payload :=  `{"hello": "world"}`
	
	//when	
	test,err := Sign(payload,HS256,shaKey)
	
	fmt.Printf("\nHS256 = %v\n",test)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.VleAUqv_-nc6dwZ9xQ8-4NiOpVRdSSrCCPCQl-7HQ2k")	
	
	//make sure we consistent with outselfs
	t,_:=Decode(test,shaKey)
	c.Assert(t, Equals, payload) 
}

func (s *TestSuite) TestEncodeHS384(c *C) {
	//given
	payload :=  `{"hello": "world"}`
	
	//when	
	test,err := Sign(payload,HS384,shaKey)
	
	fmt.Printf("\nHS384 = %v\n",test)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.VjsBP04wkLVQ9SXqN0qe-J7FHQPGhnMAXnQvVEUdDh8wsvWNEN4wVlSkGuWIIk-b")
	
	//make sure we consistent with outselfs
	t,_:=Decode(test,shaKey)
	c.Assert(t, Equals, payload)
}

func (s *TestSuite) TestEncodeHS512(c *C) {
	//given
	payload :=  `{"hello": "world"}`
	
	//when	
	test,err := Sign(payload,HS512,shaKey)
	
	fmt.Printf("\nHS512 = %v\n",test)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.IIif-Hyd8cS2_oqRb_3PzL7IwoIcPUVl_BVvOr6QbJT_x15RyNy2m_tFfUcm6lriqfAnOudqpyN-yylAXu1eFw")
	
	//make sure we consistent with outselfs
	t,_:=Decode(test,shaKey)
	c.Assert(t, Equals, payload)
}

func (s *TestSuite) TestDecodeRS256(c *C) {
	//given
	token := "eyJhbGciOiJSUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.NL_dfVpZkhNn4bZpCyMq5TmnXbT4yiyecuB6Kax_lV8Yq2dG8wLfea-T4UKnrjLOwxlbwLwuKzffWcnWv3LVAWfeBxhGTa0c4_0TX_wzLnsgLuU6s9M2GBkAIuSMHY6UTFumJlEeRBeiqZNrlqvmAzQ9ppJHfWWkW4stcgLCLMAZbTqvRSppC1SMxnvPXnZSWn_Fk_q3oGKWw6Nf0-j-aOhK0S0Lcr0PV69ZE4xBYM9PUS1MpMe2zF5J3Tqlc1VBcJ94fjDj1F7y8twmMT3H1PI9RozO-21R0SiXZ_a93fxhE_l_dj5drgOek7jUN9uBDjkXUwJPAyp9YPehrjyLdw"
	
	//when	
	test,err := Decode(token, PubKey())
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, `{"hello": "world"}`)
}

func (s *TestSuite) TestDecodeRS384(c *C) {
	//given
	token := "eyJhbGciOiJSUzM4NCIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.cOPca7YEOxnXVdIi7cJqfgRMmDFPCrZG1M7WCJ23U57rAWvCTaQgEFdLjs7aeRAPY5Su_MVWV7YixcawKKYOGVG9eMmjdGiKHVoRcfjwVywGIb-nuD1IBzGesrQe7mFQrcWKtYD9FurjCY1WuI2FzGPp5YhW5Zf4TwmBvOKz6j2D1vOFfGsogzAyH4lqaMpkHpUAXddQxzu8rmFhZ54Rg4T-jMGVlsdrlAAlGA-fdRZ-V3F2PJjHQYUcyS6n1ULcy6ljEOgT5fY-_8DDLLpI8jAIdIhcHUAynuwvvnDr9bJ4xIy4olFRqcUQIHbcb5-WDeWul_cSGzTJdxDZsnDuvg"
	
	//when	
	test,err := Decode(token, PubKey())
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, `{"hello": "world"}`)
}

func (s *TestSuite) TestDecodeRS512(c *C) {
	//given
	token := "eyJhbGciOiJSUzUxMiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.KP_mwCVRIxcF6ErdrzNcXZQDFGcL-Hlyocc4tIl3tJfzSfc7rz7qOLPjHpZ6UFH1ncd5TlpRc1B_pgvY-l0BNtx_s7n_QA55X4c1oeD8csrIoXQ6A6mtvdVGoSlGu2JnP6N2aqlDmlcefKqjl_Z-8nwDMGTMkDNhHKfHlIb2_Dliwxeq8LmNMREEdvNH2XVp_ffxBjiaKv2Eqbwc6I17241GCEmjDCvnagSgjX_5uu-da2H7TK2gtPJYUo8r9nzC7uzZJ5SB8suZH0COSofsP-9wvH0FESO40evCyEBylqg3bh9M9dIzeq8_bdTiC5kG93Fal44OEY8_Zm88wB_VjQ"
	
	//when	
	test,err := Decode(token, PubKey())
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, `{"hello": "world"}`)
}

func (s *TestSuite) TestEncodeRS256(c *C) {
	//given
	payload :=  `{"hello": "world"}`
	
	//when	
	test,err := Sign(payload,RS256,PrivKey())
	
	fmt.Printf("\nRS256 = %v\n",test)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.AzXfyb6BuwLgNUqVkfiKeQRctG25u3-5DJIsGyDnFxOGTet74SjW6Aabm3LSXZ2HgQ5yp8_tCfqA12oDmPiviq4muhgc0LKujTpGtFlf0fcSJQJpxSTMGQZdZnxdKpz7dCSlQNvW6j1tGy1UWkXod-kf4FZckoDkGEbnRAVVVL7xRupFtLneUJGoWZCiMz5oYAoYMUY1bVil1S6lIwUJLtgsvrQMoVIcjlivjZ8fzF3tjQdInxCjYeOKD3WQ2-n3APg-1GEJT-l_2y-scbE55TPSxo9fpHoDn7G0Kcgl8wpjY4j3KR9dEa4unJN3necd83yCMOUzs6vmFncEMTrRZw")
	
	//make sure we consistent with outselfs
	t,_:=Decode(test,PubKey())
	c.Assert(t, Equals, payload) 
}

func (s *TestSuite) TestEncodeRS384(c *C) {
	//given
	payload :=  `{"hello": "world"}`
	
	//when	
	test,err := Sign(payload,RS384,PrivKey())
	
	fmt.Printf("\nRS384 = %v\n",test)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.UW4uZuwV8UCFieKAX0IansM0u4-mYfarpim9JKD792an-HcSaq7inyI9GLt-iYflG0M_DmovC8QrjU4mP2FtWYR-Jnu4Ms467TreeDM4KOHSpPYOmdTG2N78L3JsXVZYEibHt5GHBzWUXqEnSthvSq-RHJsOXNjNVJACK2IWXc_PKvIbTVhoukZX_ejfA4B5ynEPax7Bt5mlyf9tSadfIGh1g29sm0hslPcZ9OKbwjvxWb17CdFy4gLq1bqvf7XnroeJGerYSXvbiOjulYizRXWBeDg5VKiEZWyyNt1rc9w_GNIIpY8B17jx6I0_hh_gjSMTTQoKqOp6Q2FWg7ZgLg")
	
	//make sure we consistent with outselfs
	t,_:=Decode(test,PubKey())
	c.Assert(t, Equals, payload) 
}

func (s *TestSuite) TestEncodeRS512(c *C) {
	//given
	payload :=  `{"hello": "world"}`
	
	//when	
	test,err := Sign(payload,RS512,PrivKey())
	
	fmt.Printf("\nRS512 = %v\n",test)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.EkP4VYlDO9a0ycFt6e_vSFwfI5MICvDqLCNFI779lodbs92EwBtxgzoYdgqz8E8H1ZtWEnyULsc7TkwgV-1xj_wbWVLDvQxjZ4wQfGaQBjD5yO9RTxwReWab3mtfixh7pPKi7lpmuO65sWBVnco2p1RXGsM7KtHjToRIFxu9ncA7YYdQ7i-YL1HcUHjjOc95NJzDyfqkwnaD10Wq7GM4XAixZFYYNDaz2nP7Gt8DwvEvFhtP2iPxeK3_AqhQ4T3B2GgcIDnNCjhETtx4oal-gZzujMEbrMx7ea_jdS5QpKv0EEiA2Ppv0-_4dDKELCwhmBuYzHZIGbSJUFMC_fKVqw")
	
	//make sure we consistent with outselfs
	t,_:=Decode(test,PubKey())
	c.Assert(t, Equals, payload) 
}


func (s *TestSuite) TestDecrypt_DIR_A128CBC_HS256(c *C) {
	//given
	token := "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..3lClLoerWhxIc811QXDLbg.iFd5MNk2eWDlW3hbq7vTFLPJlC0Od_MSyWGakEn5kfYbbPk7BM_SxUMptwcvDnZ5uBKwwPAYOsHIm5IjZ79LKZul9ZnOtJONRvxWLeS9WZiX4CghOLZL7dLypKn-mB22xsmSUbtizMuNSdgJwUCxEmms7vYOpL0Che-0_YrOu3NmBCLBiZzdWVtSSvYw6Ltzbch4OAaX2ye_IIemJoU1VnrdW0y-AjPgnAUA-GY7CAKJ70leS1LyjTW8H_ecB4sDCkLpxNOUsWZs3DN0vxxSQw.bxrZkcOeBgFAo3t0585ZdQ"
	
	//when	
	test,err := Decode(token, aes256Key)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, `{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}`)
}

func (s *TestSuite) TestDecrypt_DIR_A192CBC_HS384(c *C) {
	//given
	token := "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0..fX42Nn8ABHClA0UfbpkX_g.ClZzxQIzg40GpTETaLejGNhCN0mqSM1BNCIU5NldeF-hGS7_u_5uFsJoWK8BLCoWRtQ3cWIeaHgOa5njCftEK1AoHvechgNCQgme-fuF3f2v5DOphU-tveYzN-uvrUthS0LIrAYrwQW0c0DKcJZ-9vQmC__EzesZgUHiDB8SnoEROPTvJcsBKI4zhFT7wOgqnFS7P7_BQZj_UnbJkzTAiE5MURBBpCYR-OS3zn--QftbdGVJ2CWmwH3HuDO9-IE2IQ5cKYHnzSwu1vyME_SpZA.qd8ZGKzmOzzPhFV-Po8KgJ5jZb5xUQtU"
	
	//when	
	test,err := Decode(token, aes384Key)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, `{"exp":1392553372,"sub":"alice","nbf":1392552772,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"f81648e9-e9b3-4e37-a655-fcfacace0ef0","iat":1392552772}`)
}

func (s *TestSuite) TestDecrypt_DIR_A256CBC_HS512(c *C) {
	//given
	token := "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..ZD93XtD7TOa2WMbqSuaY9g.1J5BAuxNRMWaw43s7hR82gqLiaZOHBmfD3_B9k4I2VIDKzS9oEF_NS2o7UIBa6t_fWHU7vDm9lNAN4rqq7OvtCBHJpFk31dcruQHxwYKn5xNefG7YP-o6QtpyNioNWJpaSD5VRcRO5ufRrw2bu4_nOth00yJU5jjN3O3n9f-0ewrN2UXDJIbZM-NiSuEDEgOVHImQXoOtOQd0BuaDx6xTJydw_rW5-_wtiOH2k-3YGlibfOWNu51kApGarRsAhhqKIPetYf5Mgmpv1bkUo6HJw.nVpOmg3Sxri0rh6nQXaIx5X0fBtCt7Kscg6c66NugHY"
	
	//when	
	test,err := Decode(token, aes512Key)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, `{"exp":1392553617,"sub":"alice","nbf":1392553017,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"029ea059-b8aa-44eb-a5ad-59458de678f8","iat":1392553017}`)
}

func (s *TestSuite) TestEncrypt_DIR_A128CBC_HS256(c *C) {
	//given
	payload :=  `{"hello": "world"}`
	
	//when	
	test,err := Encrypt(payload,DIR,A128CBC_HS256,aes256Key)
	
	fmt.Printf("\nDIR A128CBC-HS256 = %v\n",test)
	
	//then
	c.Assert(err, IsNil)
	
	parts := strings.Split(test,".")
	
    c.Assert(len(parts), Equals, 5);
	c.Assert(parts[0],Equals,"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0")
	c.Assert(len(parts[1]), Equals, 0);
	c.Assert(len(parts[2]), Equals, 22);	
	c.Assert(len(parts[3]), Equals, 43);	
	c.Assert(len(parts[4]), Equals, 22);	
    	
	//make sure we consistent with outselfs
	t,_:=Decode(test, aes256Key)
	c.Assert(t, Equals, payload) 
}

func (s *TestSuite) TestEncrypt_DIR_A192CBC_HS384(c *C) {
	//given
	payload :=  `{"hello": "world"}`
	
	//when	
	test,err := Encrypt(payload,DIR,A192CBC_HS384,aes384Key)
	
	fmt.Printf("\nDIR A192CBC-HS384 = %v\n",test)
	
	//then
	c.Assert(err, IsNil)
	
	parts := strings.Split(test,".")
	
    c.Assert(len(parts), Equals, 5);
	c.Assert(parts[0],Equals,"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0")
	c.Assert(len(parts[1]), Equals, 0);
	c.Assert(len(parts[2]), Equals, 22);	
	c.Assert(len(parts[3]), Equals, 43);	
	c.Assert(len(parts[4]), Equals, 32);	
	
	//make sure we consistent with outselfs
	t,_:=Decode(test, aes384Key)
	c.Assert(t, Equals, payload) 
}

func (s *TestSuite) TestEncrypt_DIR_A256CBC_HS512(c *C) {
	//given
	payload :=  `{"hello": "world"}`
	
	//when	
	test,err := Encrypt(payload,DIR,A256CBC_HS512,aes512Key)
	
	fmt.Printf("\nDIR A256CBC-HS512 = %v\n",test)
	
	//then
	c.Assert(err, IsNil)
	
	parts := strings.Split(test,".")
	
    c.Assert(len(parts), Equals, 5);
	c.Assert(parts[0],Equals,"eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0")
	c.Assert(len(parts[1]), Equals, 0);
	c.Assert(len(parts[2]), Equals, 22);	
	c.Assert(len(parts[3]), Equals, 43);	
	c.Assert(len(parts[4]), Equals, 43);	
	
	//make sure we consistent with outselfs
	t,_:=Decode(test, aes512Key)
	c.Assert(t, Equals, payload) 
}

func (s *TestSuite) TestDecrypt_DIR_A128GCM(c *C) {
	//given
	token := "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..yVi-LdQQngN0C5WS.1McwSmhZzAtmmLp9y-OdnJwaJFo1nj_4ashmzl2LhubGf0Jl1OTEVJzsHZb7bkup7cGTkuxh6Vfv10ljHsjWf_URXoxP3stQqQeViVcuPV0y2Q_WHYzTNGZpmHGe-hM6gjDhyZyvu3yeXGFSvfPQmp9pWVOgDjI4RC0MQ83rzzn-rRdnZkznWjbmOPxwPrR72Qng0BISsEwbkPn4oO8-vlHkVmPpuDTaYzCT2ZR5K9JnIU8d8QdxEAGb7-s8GEJ1yqtd_w._umbK59DAKA3O89h15VoKQ"
	
	//when	
	test,err := Decode(token, aes128Key)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, `{"exp":1392548520,"sub":"alice","nbf":1392547920,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"0e659a67-1cd3-438b-8888-217e72951ec9","iat":1392547920}`)
}

func (s *TestSuite) TestDecrypt_DIR_A192GCM(c *C) {
	//given
	token := "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyR0NNIn0..YW2WB0afVronbgSz.tfk1VADGjBnViYD7He5mbhxpbogoT1cmhKiDKzzoBV2AxfsgJ2Eq-vtEqPi9eY9H52FLLtht26rc5fPz9ZKOUH2hYeFdaRyKYXlpEnUR2cCT9_3TYcaFhpYBH4HCa59NruKlJHMBqM2ssWZLSEblFX9srUHFtu2OQz2ydMy1fr8ABDTdVYgaqyBoYRGykTkEsgayEyfAMz9u095N2J0JTCB5Q0IiXNdBzBSxZXG-i9f5HFEb6IliaTwFTNFnhDL66O4rsg._dh02z25W7HA6b1XiFVpUw"
	
	//when	
	test,err := Decode(token, aes192Key)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, `{"exp":1392552631,"sub":"alice","nbf":1392552031,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"a3fea096-2e96-4d8b-b7cd-070e08b533fb","iat":1392552031}`)
}

func (s *TestSuite) TestDecrypt_DIR_A256GCM(c *C) {
	//given
	token := "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Fmz3PLVfv-ySl4IJ.LMZpXMDoBIll5yuEs81Bws2-iUUaBSpucJPL-GtDKXkPhFpJmES2T136Vd8xzvp-3JW-fvpRZtlhluqGHjywPctol71Zuz9uFQjuejIU4axA_XiAy-BadbRUm1-25FRT30WtrrxKltSkulmIS5N-Nsi_zmCz5xicB1ZnzneRXGaXY4B444_IHxGBIS_wdurPAN0OEGw4xIi2DAD1Ikc99a90L7rUZfbHNg_iTBr-OshZqDbR6C5KhmMgk5KqDJEN8Ik-Yw.Jbk8ZmO901fqECYVPKOAzg"
	
	//when	
	test,err := Decode(token, aes256Key)
	
	//then
	c.Assert(err, IsNil)
	c.Assert(test, Equals, `{"exp":1392552841,"sub":"alice","nbf":1392552241,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"efdfc02f-945e-4e1f-85a6-9f240f6cf153","iat":1392552241}`)
}

func (s *TestSuite) TestEncrypt_DIR_A128GCM(c *C) {
	//given
	payload :=  `{"hello": "world"}`
	
	//when	
	test,err := Encrypt(payload,DIR,A128GCM,aes128Key)
	
	fmt.Printf("\nDIR A128GCM = %v\n",test)
	
	//then
	c.Assert(err, IsNil)
	
	parts := strings.Split(test,".")
	
    c.Assert(len(parts), Equals, 5);
	c.Assert(parts[0],Equals,"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0")
	c.Assert(len(parts[1]), Equals, 0);
	c.Assert(len(parts[2]), Equals, 16);
	c.Assert(len(parts[3]), Equals, 24);
	c.Assert(len(parts[4]), Equals, 22);
	
	//make sure we consistent with outselfs
	t,_:=Decode(test, aes128Key)
	c.Assert(t, Equals, payload) 
}

func (s *TestSuite) TestEncrypt_DIR_A192GCM(c *C) {
	//given
	payload :=  `{"hello": "world"}`
	
	//when	
	test,err := Encrypt(payload,DIR,A192GCM,aes192Key)
	
	fmt.Printf("\nDIR A192GCM = %v\n",test)
	
	//then
	c.Assert(err, IsNil)
	
	parts := strings.Split(test,".")
	
    c.Assert(len(parts), Equals, 5);
	c.Assert(parts[0],Equals,"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyR0NNIn0")
	c.Assert(len(parts[1]), Equals, 0);
	c.Assert(len(parts[2]), Equals, 16);
	c.Assert(len(parts[3]), Equals, 24);
	c.Assert(len(parts[4]), Equals, 22);
	
	//make sure we consistent with outselfs
	t,_:=Decode(test, aes192Key)
	c.Assert(t, Equals, payload) 
}

func (s *TestSuite) TestEncrypt_DIR_A256GCM(c *C) {
	//given
	payload :=  `{"hello": "world"}`
	
	//when	
	test,err := Encrypt(payload,DIR,A256GCM,aes256Key)
	
	fmt.Printf("\nDIR A256GCM = %v\n",test)
	
	//then
	c.Assert(err, IsNil)
	
	parts := strings.Split(test,".")
	
    c.Assert(len(parts), Equals, 5);
	c.Assert(parts[0],Equals,"eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0")
	c.Assert(len(parts[1]), Equals, 0);
	c.Assert(len(parts[2]), Equals, 16);
	c.Assert(len(parts[3]), Equals, 24);
	c.Assert(len(parts[4]), Equals, 22);
	
	//make sure we consistent with outselfs
	t,_:=Decode(test, aes256Key)
	c.Assert(t, Equals, payload) 
}

//test utils
func PubKey() *rsa.PublicKey {
	key,_ :=Rsa.NewPublic([]byte(pubKey))	
	return key	
}


func PrivKey() *rsa.PrivateKey {
	key,_ :=Rsa.NewPrivate([]byte(privKey))	
	return key	
}
