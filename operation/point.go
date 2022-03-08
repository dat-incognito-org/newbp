package operation

import (
	"encoding/hex"
	"fmt"

	"filippo.io/edwards25519"
	operation_old "github.com/incognitochain/incognito-chain/privacy/operation"
)

type Point struct {
	p edwards25519.Point
}

func RandomPoint() *Point {
	sc := RandomScalar()
	return NewIdentityPoint().ScalarMultBase(sc)
}

func NewGeneratorPoint() *Point {
	return &Point{ *edwards25519.NewGeneratorPoint() }
}

func NewIdentityPoint() *Point {
	return &Point{ *edwards25519.NewIdentityPoint() }
}

// TODO
func (p Point) PointValid() bool {
	return true
	// var point C25519.ExtendedGroupElement
	// isValid := point.FromBytes(&p.key)
	// if !isValid {
	// 	return false
	// }
	// lP := new(Point).ScalarMult(&p, curveOrder)
	// return lP.IsIdentity()
}

func (p *Point) Set(q *Point) *Point {
	temp := edwards25519.NewIdentityPoint()
	temp.Set(&q.p)
	p.p = *temp
	return p
}

func (p Point) String() string {
	return fmt.Sprintf("%x", p.ToBytesS())
}

func (p Point) MarshalText() []byte {
	return []byte(hex.EncodeToString(p.ToBytesS()))
}

func (p Point) Show() string {
	return hex.EncodeToString(p.ToBytesS())[:8]
}

func (p *Point) UnmarshalText(data []byte) (*Point, error) {
	byteSlice, _ := hex.DecodeString(string(data))
	if len(byteSlice) != Ed25519KeySize {
		return nil, fmt.Errorf("invalid point byte size")
	}
	_, err := p.p.SetBytes(byteSlice)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p Point) ToBytesS() []byte {
	return p.p.Bytes()
}

func (p *Point) FromBytesS(b []byte) (*Point, error) {
	if len(b) != Ed25519KeySize {
		return nil, fmt.Errorf("invalid point byte Size")
	}
	_, err := p.p.SetBytes(b)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// func (p *Point) FromBytesS(b []byte) (*Point, error) {
// 	if len(b) != Ed25519KeySize {
// 		return nil, fmt.Errorf("Invalid Ed25519 Key Size")
// 	}

// 	if p == nil {
// 		p = new(Point)
// 	}
// 	var array [Ed25519KeySize]byte
// 	copy(array[:], b)
// 	p.key.FromBytes(array)

// 	var point C25519.ExtendedGroupElement
// 	if !point.FromBytes(&p.key) {
// 		return nil, fmt.Errorf("Invalid point value")
// 	}

// 	return p, nil
// }

func (p *Point) Identity() *Point {
	p.p = *edwards25519.NewIdentityPoint()
	return p
}

func (p Point) IsIdentity() bool {
	return p.p.Equal(edwards25519.NewIdentityPoint()) == 1
}

// does a * G where a is a scalar and G is the curve basepoint
func (p *Point) ScalarMultBase(a *Scalar) *Point {
	temp := edwards25519.NewIdentityPoint()
	temp.ScalarBaseMult(&a.s)
	p.p = *temp
	return p
}

func (p *Point) ScalarMult(pa *Point, a *Scalar) *Point {
	temp := edwards25519.NewIdentityPoint()
	temp.ScalarMult(&a.s, &pa.p)
	p.p = *temp
	return p
}

func (p *Point) MultiScalarMult(scalarLs []*Scalar, pointLs []*Point) *Point {
	l := len(scalarLs)
	// must take inputs of the same length
	if l != len(pointLs) {
		panic("Cannot MultiscalarMul with different size inputs")
	}

	scalarKeyLs := make([]*edwards25519.Scalar, l)
	pointKeyLs := make([]*edwards25519.Point, l)
	for i := 0; i < l; i++ {
		scalarKeyLs[i] = &scalarLs[i].s
		pointKeyLs[i] = &pointLs[i].p
	}
	temp := edwards25519.NewIdentityPoint()
	temp.MultiScalarMult(scalarKeyLs, pointKeyLs)
	p.p = *temp
	return p
}

func (p *Point) VarTimeMultiScalarMult(scalarLs []*Scalar, pointLs []*Point) *Point {
	l := len(scalarLs)
	// must take inputs of the same length
	if l != len(pointLs) {
		panic("Cannot MultiscalarMul with different size inputs")
	}

	scalarKeyLs := make([]*edwards25519.Scalar, l)
	pointKeyLs := make([]*edwards25519.Point, l)
	for i := 0; i < l; i++ {
		scalarKeyLs[i] = &scalarLs[i].s
		pointKeyLs[i] = &pointLs[i].p
	}
	temp := edwards25519.NewIdentityPoint()
	temp.VarTimeMultiScalarMult(scalarKeyLs, pointKeyLs)
	p.p = *temp
	return p
}

// func (p *Point) InvertScalarMultBase(a *Scalar) *Point {
// 	if p == nil {
// 		p = new(Point)
// 	}
// 	inv := new(Scalar).Invert(a)
// 	p.ScalarMultBase(inv)
// 	return p
// }

// func (p *Point) InvertScalarMult(pa *Point, a *Scalar) *Point {
// 	inv := new(Scalar).Invert(a)
// 	p.ScalarMult(pa, inv)
// 	return p
// }

// func (p *Point) Derive(pa *Point, a *Scalar, b *Scalar) *Point {
// 	c := new(Scalar).Add(a, b)
// 	return p.InvertScalarMult(pa, c)
// }

func (p *Point) Add(pa, pb *Point) *Point {
	temp := edwards25519.NewIdentityPoint()
	temp.Add(&pa.p, &pb.p)
	p.p = *temp
	return p
}

// aA + bB
func (p *Point) AddPedersen(a *Scalar, A *Point, b *Scalar, B *Point) *Point {
	result := NewIdentityPoint().MultiScalarMult([]*Scalar{a, b}, []*Point{A, B})
	p = result
	return result
}

func IsPointEqual(pa *Point, pb *Point) bool {
	return pa.p.Equal(&pb.p) == 1
}

func HashToPointFromIndex(index int64, padStr string) *Point {
	msg := edwards25519.NewGeneratorPoint().Bytes()
	msg = append(msg, []byte(padStr)...)
	msg = append(msg, []byte(string(index))...)

	return HashToPoint(msg)
}

// legacy map-to-point
func HashToPoint(b []byte) *Point {
	temp := operation_old.HashToPoint(b)
	result := &Point{}
	result.FromBytesS(temp.ToBytesS())
	return result
}
