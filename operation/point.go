package operation

import (
	"encoding/hex"
	"fmt"

	"filippo.io/edwards25519"
)

type Point struct {
	p edwards25519.Point
}

func RandomPoint() *Point {
	sc := RandomScalar()
	return new(Point).ScalarMultBase(sc)
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
	p.p.Set(&q.p)
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
	p.p.ScalarBaseMult(&a.s)
	return p
}

func (p *Point) ScalarMult(pa *Point, a *Scalar) *Point {
	p.p.ScalarMult(&a.s, &pa.p)
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
	p.p.MultiScalarMult(scalarKeyLs, pointKeyLs)
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
	p.p.VarTimeMultiScalarMult(scalarKeyLs, pointKeyLs)
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
	p.p.Add(&pa.p, &pb.p)
	return p
}

// aA + bB
func (p *Point) AddPedersen(a *Scalar, A *Point, b *Scalar, B *Point) *Point {
	return p.VarTimeMultiScalarMult([]*Scalar{a, b}, []*Point{A, B})
}

// func (p *Point) AddPedersenCached(a *Scalar, APreCompute [8]C25519.CachedGroupElement, b *Scalar, BPreCompute [8]C25519.CachedGroupElement) *Point {
// 	if p == nil {
// 		p = new(Point)
// 	}

// 	var key C25519.Key
// 	C25519.AddKeys3_3(&key, &a.key, &APreCompute, &b.key, &BPreCompute)
// 	p.key = key
// 	return p
// }

// func (p *Point) Sub(pa, pb *Point) *Point {
// 	if p == nil {
// 		p = new(Point)
// 	}
// 	res := p.key
// 	C25519.SubKeys(&res, &pa.key, &pb.key)
// 	p.key = res
// 	return p
// }

func IsPointEqual(pa *Point, pb *Point) bool {
	return pa.p.Equal(&pb.p) == 1
}

func HashToPointFromIndex(index int64, padStr string) *Point {
	msg := edwards25519.NewGeneratorPoint().Bytes()[:]
	msg = append(msg, []byte(padStr)...)
	msg = append(msg, []byte(string(index))...)
	h := Keccak256(msg)

	return HashToPoint(h[:])
}

func HashToPoint(b []byte) *Point {
	// h := Keccak256(b)
	// h = Keccak256(h[:])
	// sc := (&Scalar{}).FromBytesS(h)
	// if err != nil {
	// 	panic(fmt.Errorf("unexpected. will fix %v", err))
	// }
	// TODO: use legacy mapper
	return  (&Point{}).ScalarMultBase(HashToScalar(b))
}
