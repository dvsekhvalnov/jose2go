package compact

import (
	"strings"
	"jose2go/base64url"
)

func Parse(token string) [][]byte {
	parts:=strings.Split(token,".")
	
	result:=make([][]byte,len(parts))
		
	for i,part:=range parts	{
		result[i],_=base64url.Decode(part) //TODO: suppressing error here
	}
		
	return result
}

func Serialize(parts ...[]byte) string {
	result:=make([]string,len(parts))
	
	for i,part:=range parts {
		result[i]=base64url.Encode(part)
	}
	
	return strings.Join(result,".")
}