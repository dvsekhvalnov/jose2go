package padding

import (
	"bytes"
)

func Align(data []byte, bitSize int) []byte {
	
	actual:=len(data)	
	required:=bitSize >> 3
	
	if (bitSize % 8) > 0 {
		required++  //extra byte if needed
	}
	
	if (actual >= required) {
		return data
	} 
	
	return append(bytes.Repeat([]byte{0}, required-actual), data...)
}