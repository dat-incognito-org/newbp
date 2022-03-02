package main 

import (
	"fmt"

	"github.com/dat-incognito-org/newbp/bulletproofs"
	_ "github.com/dat-incognito-org/newbp/operation"
)

func main(){
	fmt.Println("prove")
	res := bulletproofs.ExtProve([]uint64{1, 2, 3, 4}, [][32]byte{[32]byte{1}, [32]byte{2}, [32]byte{3}, [32]byte{4}})
	fmt.Printf("%x\n", res)
}