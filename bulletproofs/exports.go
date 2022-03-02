package bulletproofs

/* #cgo LDFLAGS: -L${SRCDIR}/../target/release -lnewbp
#include "../ext.h"
#include "stdio.h"
Vec_uint8_t prove(Vec_uint64_t witness, Vec_uint8_32_array_t blindings)
{
  return bulletproofs_prove_multiple(&witness, &blindings);
}
*/
import "C"
import (
    "unsafe"
    // "fmt"
)

var Mynum = 42

func ExtProve(wits []uint64, rands [][32]byte) []byte{
    w := (&c_uint64_slice{}).from(wits)
    r := (&c_bytes32_slice{}).from(rands)
    c := C.prove(
        *(*C.Vec_uint64_t)(unsafe.Pointer(w)),
        *(*C.Vec_uint8_32_array_t)(unsafe.Pointer(r)),
    )
    p := (*[]byte)(unsafe.Pointer(&c.ptr))
    result := make([]byte, c.len)
    copy(result, *p)
    return result
}

func (b *c_bytes32) from(_b [32]byte) *c_bytes32 {
    b.Idx = _b
    return b
}

func (bs *c_bytes32_slice) from(_bs [][32]byte) *c_bytes32_slice {
    temp := make([]c_bytes32, len(_bs))
    for i, val := range _bs {
        temp[i] = *(&c_bytes32{}).from(val)
    }
    bs.Ptr = &temp[0]
    bs.Len = uint64(len(_bs))
    bs.Cap = uint64(len(_bs))
    return bs
}

func (ns *c_uint64_slice) from(_ns []uint64) *c_uint64_slice {
    ns.Ptr = &_ns[0]
    ns.Len = uint64(len(_ns))
    ns.Cap = uint64(len(_ns))
    return ns
}
