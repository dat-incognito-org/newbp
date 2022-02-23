package main

/* #cgo LDFLAGS: -L${SRCDIR}/target/release -lnewbp
#include "ext.h"
Vec_uint8_t naiveProve()
{
  return naive_prove();
}
*/
import "C"
import (
    "fmt"
    "unsafe"
)

func main(){
    c := C.naiveProve()
    p := (*[]byte)(unsafe.Pointer(&c.ptr))
    result := make([]byte, c.len)
    copy(result, *p)
    fmt.Println("%+v", c)
    fmt.Printf("%x", result)
}