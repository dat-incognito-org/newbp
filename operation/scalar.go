package operation

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"

	"filippo.io/edwards25519"
	operation_old "github.com/incognitochain/incognito-chain/privacy/operation"
)

type Scalar struct {
	s edwards25519.Scalar
}

func NewScalar() *Scalar{
	return &Scalar{ *edwards25519.NewScalar() }
}

var ScZero = NewScalar().FromUint64(0)
var ScOne = NewScalar().FromUint64(1)
var ScMinusOne = NewScalar().Sub(ScZero, ScOne)

func (sc Scalar) String() string {
	return fmt.Sprintf("%x", sc.ToBytesS())
}

func (sc Scalar) MarshalText() []byte {
	return []byte(hex.EncodeToString(sc.ToBytesS()))
}

func (sc *Scalar) UnmarshalText(data []byte) (*Scalar, error) {
	byteSlice, _ := hex.DecodeString(string(data))
	if len(byteSlice) != Ed25519KeySize {
		return nil, fmt.Errorf("invalid scalar byte size")
	}
	return sc.FromBytesS(byteSlice), nil
}

func (sc Scalar) ToBytesS() []byte {
	return sc.s.Bytes()
}

func (sc *Scalar) FromBytesS(b []byte) *Scalar {
	var array [Ed25519KeySize]byte
	copy(array[:], b)
	sc.s.SetCanonicalBytes(array[:])
	return sc
}

// func (sc *Scalar) SetKey(a *C25519.Key) (*Scalar, error) {
// 	if sc == nil {
// 		sc = new(Scalar)
// 	}
// 	sc.key = *a
// 	if sc.ScalarValid() == false {
// 		return nil, fmt.Errorf("Invalid key value")
// 	}
// 	return sc, nil
// }

func (sc *Scalar) Set(a *Scalar) *Scalar {
	sc.s.Set(&a.s)
	return sc
}

func RandomScalar() *Scalar {
	b := make([]byte, 64)
	rand.Read(b)
	res, _ := edwards25519.NewScalar().SetUniformBytes(b)
	return &Scalar{*res}
}

func HashToScalar(data []byte) *Scalar {
	temp := operation_old.HashToScalar(data)
	// h = Keccak256(h[:])
	sc := (&Scalar{}).FromBytesS(temp.ToBytesS())
	return sc
}

func (sc *Scalar) FromUint64(i uint64) *Scalar {
	num := big.NewInt(0).SetUint64(i)
	bSlice := num.FillBytes(make([]byte, 32))
	var b [32]byte
	copy(b[:], bSlice)
	rev := Reverse(b)
	sc.s.SetCanonicalBytes(rev[:])
	return sc
}

func (sc *Scalar) ToUint64Little() uint64 {
	var b [32]byte
	copy(b[:], sc.s.Bytes())
	rev := Reverse(b)
	keyBN := big.NewInt(0).SetBytes(rev[:])
	return keyBN.Uint64()
}

func (sc *Scalar) Add(a, b *Scalar) *Scalar {
	sc.s.Add(&a.s, &b.s)
	return sc
}

func (sc *Scalar) Sub(a, b *Scalar) *Scalar {
	sc.s.Subtract(&a.s, &b.s)
	return sc
}

func (sc *Scalar) Mul(a, b *Scalar) *Scalar {
	sc.s.Multiply(&a.s, &b.s)
	return sc
}

// a*b + c % l
func (sc *Scalar) MulAdd(a, b, c *Scalar) *Scalar {
	sc.s.MultiplyAdd(&a.s, &b.s, &c.s)
	return sc
}

// func (sc *Scalar) Exp(a *Scalar, v uint64) *Scalar {
// 	if sc == nil {
// 		sc = new(Scalar)
// 	}

// 	var res C25519.Key
// 	C25519.ScMul(&res, &a.key, &a.key)
// 	for i := 0; i < int(v)-2; i++ {
// 		C25519.ScMul(&res, &res, &a.key)
// 	}

// 	sc.key = res
// 	return sc
// }

func (sc *Scalar) ScalarValid() bool {
	// TODO
	return true
}

// func (sc *Scalar) IsOne() bool {
// 	s := sc.s
// 	return ((int(s[0]|s[1]|s[2]|s[3]|s[4]|s[5]|s[6]|s[7]|s[8]|
// 		s[9]|s[10]|s[11]|s[12]|s[13]|s[14]|s[15]|s[16]|s[17]|
// 		s[18]|s[19]|s[20]|s[21]|s[22]|s[23]|s[24]|s[25]|s[26]|
// 		s[27]|s[28]|s[29]|s[30]|s[31])-1)>>8)+1 == 1
// }

func IsScalarEqual(sc1, sc2 *Scalar) bool {
	return sc1.s.Equal(&sc2.s) == 1
}

func Compare(sca, scb *Scalar) int {
	tmpa := sca.ToBytesS()
	tmpb := scb.ToBytesS()

	for i := Ed25519KeySize - 1; i >= 0; i-- {
		if uint64(tmpa[i]) > uint64(tmpb[i]) {
			return 1
		}

		if uint64(tmpa[i]) < uint64(tmpb[i]) {
			return -1
		}
	}
	return 0
}

// func (sc *Scalar) IsZero() bool {
// 	if sc == nil {
// 		return false
// 	}
// 	return C25519.ScIsZero(&sc.key)
// }

func CheckDuplicateScalarArray(arr []*Scalar) bool {
	sort.Slice(arr, func(i, j int) bool {
		return Compare(arr[i], arr[j]) == -1
	})

	for i := 0; i < len(arr)-1; i++ {
		if IsScalarEqual(arr[i], arr[i+1]) == true {
			return true
		}
	}
	return false
}

func (sc *Scalar) Invert(a *Scalar) *Scalar {
	sc.s.Invert(&a.s)
	return sc
}

func Reverse(x [32]byte) (result [32]byte) {
	result = x
	// A key is in little-endian, but the big package wants the bytes in
	// big-endian, so Reverse them.
	blen := len(x) // its hardcoded 32 bytes, so why do len but lets do it
	for i := 0; i < blen/2; i++ {
		result[i], result[blen-1-i] = result[blen-1-i], result[i]
	}
	return
}

func d2h(val uint64) [32]byte {
	var key [32]byte
	for i := 0; val > 0; i++ {
		key[i] = byte(val & 0xFF)
		val /= 256
	}
	return key
}
