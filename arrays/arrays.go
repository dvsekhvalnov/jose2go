package arrays

import (
	"encoding/binary"
	"bytes"
	"jose2go/base64url"
	"crypto/rand"
	"fmt"		
)

func Xor(left,right []byte) []byte {
	result:=make([]byte,len(left))
	
	for i:=0;i<len(left);i++ {
		result[i]=left[i] ^ right[i]
	}
	
	return result
}

func Slice(arr []byte, count int) [][]byte {
	
	sliceCount := len(arr) / count;
	result:=make([][]byte, sliceCount)
	
	for i:=0; i<sliceCount; i++ {
		start:=i*count
		end:=i*count+count

		result[i]=arr[start:end]
	}
	
	return result
}

func Random(byteCount int) ([]byte,error) {
	data := make([]byte,byteCount)
	
	if _, err := rand.Read(data);err!=nil {
		return nil,err
	}
   
	return data,nil
}

func Concat(arrays ...[]byte) []byte {
	var result []byte=arrays[0]
	
	for _,arr := range(arrays[1:]) {
		result=append(result,arr...)
	}
	
	return result
}

func Unwrap(arrays [][]byte) []byte {
	var result []byte=arrays[0]
	
	for _,arr := range(arrays[1:]) {
		result=append(result,arr...)
	}
	
	return result
}

func UInt64ToBytes(value uint64) []byte {
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, value)
	
	return result
}

func UInt32ToBytes(value uint32) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, value)
	
	return result
}

func Dump(arr []byte) string {
	var buf bytes.Buffer    
	
	buf.WriteString("(")
	buf.WriteString(fmt.Sprintf("%v",len(arr)))
	buf.WriteString(" bytes)[")

	for idx,b := range(arr) {
		buf.WriteString(fmt.Sprintf("%v",b))
		if idx!=len(arr)-1 {
			buf.WriteString(", ")
		}
	}

	buf.WriteString("], Hex: [")	

	for idx,b := range(arr) {
		buf.WriteString(fmt.Sprintf("%X",b))
		if idx!=len(arr)-1 {
			buf.WriteString(" ")
		}
	}

	buf.WriteString("], Base64Url:")	
	buf.WriteString(base64url.Encode(arr))
		
	return buf.String()	
}