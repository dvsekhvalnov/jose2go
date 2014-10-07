package kdf

import (
	"hash"
	"math"
	"jose2go/arrays"
)



func DeriveConcatKDF(keydatalen int, sharedSecret, algId, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo []byte, h hash.Hash) []byte {
	
	otherInfo := arrays.Concat(algId, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo)
	
	keyLenBytes := keydatalen >> 3
	
	reps := int(math.Ceil(float64(keyLenBytes) / float64(h.Size())))
	
	if reps > 4294967295 {
		panic("kdf.DeriveConcatKDF: too much iterations (more than 2^32-1).")
	}
	
	dk:=make([]byte, 0, keyLenBytes)
	
	for counter := 1;counter <= reps;counter++ {
		h.Reset()

		counterBytes:=arrays.UInt32ToBytes(uint32(counter))
						
		h.Write(counterBytes)
		h.Write(sharedSecret)		
		h.Write(otherInfo)
		
		dk = h.Sum(dk)
	}

	return dk[:keyLenBytes]	
}