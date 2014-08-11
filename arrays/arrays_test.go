package arrays

import (
	"testing"	
	// "fmt"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }
type TestSuite struct{}
var _ = Suite(&TestSuite{})

func (s *TestSuite) TestConcat(c *C) {
	//given
	a:=[]byte{1,2,3}
	b:=[]byte{4,5}
	d:=[]byte{6}	
	e:=[]byte{}
	f:=[]byte{7,8,9,10}
	
	//when	
	test:=Concat(a,b,d,e,f)
	
	//then
	c.Assert(test, DeepEquals, []byte{1,2,3,4,5,6,7,8,9,10})
}