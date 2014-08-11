package base64url

import (
	"strings"
	"encoding/base64"
)

func Decode(data string) ([]byte,error) {
	data = strings.Replace(data, "-", "+", -1) // 62nd char of encoding
	data = strings.Replace(data, "_", "/", -1) // 63rd char of encoding
	
	switch(len(data) % 4) { // Pad with trailing '='s
		case 0:             // no padding
		case 2: data+="=="  // 2 pad chars
		case 3:	data+="="   // 1 pad char		
	}
		
	return base64.StdEncoding.DecodeString(data)
}

func Encode(data []byte) string {
	result := base64.StdEncoding.EncodeToString(data)
	result = strings.Replace(result, "+", "-", -1) // 62nd char of encoding
	result = strings.Replace(result, "/", "_", -1) // 63rd char of encoding
	result = strings.Replace(result, "=", "", -1)  // Remove any trailing '='s
	
	return result
}