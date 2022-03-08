package bulletproofs

import (
	crypto_rand "crypto/rand"
	"fmt"
	"math/rand"
	"testing"

	"github.com/dat-incognito-org/newbp/operation"
	"github.com/incognitochain/incognito-chain/common"
	operation_old "github.com/incognitochain/incognito-chain/privacy/operation"
	C25519 "github.com/incognitochain/incognito-chain/privacy/operation/curve25519"
	bulletproofs_old "github.com/incognitochain/incognito-chain/privacy/privacy_v2/bulletproofs"
	. "github.com/stretchr/testify/assert"
)

var _ = func() (_ struct{}) {
	Logger.Init(common.NewBackend(nil).Logger("test", true))
	return
}()

var rangeProof1 *AggregatedRangeProof
var rangeProof2 *bulletproofs_old.AggregatedRangeProof

type fnProve = func(values []uint64, rands []*operation.Scalar, rands2 []*operation_old.Scalar)

var provers = map[string]fnProve{
	"Go&old-curve-impl": func(values []uint64, rands []*operation.Scalar, rands2 []*operation_old.Scalar) {
		wit := new(bulletproofs_old.AggregatedRangeWitness)
		wit.Set(values, rands2)
		proof, err := wit.Prove()
		if err != nil {
			panic(err)
		}
		rangeProof2 = proof
	},
	"Go&new-curve-impl": func(values []uint64, rands []*operation.Scalar, rands2 []*operation_old.Scalar) {
		wit := new(AggregatedRangeWitness)
		wit.Set(values, rands)
		proof, err := wit.Prove()
		if err != nil {
			panic(err)
		}
		rangeProof1 = proof
	},
	"Dalek-cgo": func(values []uint64, rands []*operation.Scalar, rands2 []*operation_old.Scalar) {
		randsRaw := make([][32]byte, len(rands))
		for i, val := range rands {
			copy(randsRaw[i][:], val.ToBytesS())
		}
		// ignore scalar marshaling time
		ExtProve(values, randsRaw)
	},
}

type fnProveVerify = func()

var pverifiers = map[string]fnProveVerify{
	"Go&old-curve-impl": func() {
		valid, err := rangeProof2.Verify()
		if !valid || err != nil {
			panic(err)
		}
	},
	"Go&new-curve-impl": func() {
		valid, err := rangeProof1.VerifyFaster()
		if !valid || err != nil {
			panic(err)
		}
	},
}

type fnRandomScalarMult = func()

var pointMults = map[string]fnRandomScalarMult{
	"dero-base": func() {
		sc := operation_old.RandomScalar()
		(&operation_old.Point{}).ScalarMultBase(sc)
	},
	"newed-base": func() {
		sc := operation.RandomScalar()
		(&operation.Point{}).ScalarMultBase(sc)
	},
	"dero-point": func() {
		sc := operation_old.RandomScalar()
		(&operation_old.Point{}).ScalarMult(operation_old.PedCom.G[0], sc)
	},
	"newed-point": func() {
		sc := operation.RandomScalar()
		(&operation.Point{}).ScalarMult(operation.NewGeneratorPoint(), sc)
	},
	"legacy-map-to-point": func() {
		b := make([]byte, 32)
		crypto_rand.Read(b)
		operation_old.HashToPoint(b)
	},
}

type fnRandomMultiScalarMult = func([][]byte)

var multiScalarMults = map[string]fnRandomMultiScalarMult{
	"dero-multi": func(points [][]byte) {
		var sLst []*operation_old.Scalar
		var pLst []*operation_old.Point
		for _, rawPoint := range points {
			sLst = append(sLst, operation_old.RandomScalar())
			var temp operation_old.Point
			_, err := temp.FromBytesS(rawPoint)
			if err != nil {
				panic(err)
			}
			pLst = append(pLst, &temp)
		}
		p := &operation_old.Point{}
		p.MultiScalarMult(sLst, pLst)
	},
	"newed-multi": func(points [][]byte) {
		var sLst []*operation.Scalar
		var pLst []*operation.Point
		for _, rawPoint := range points {
			sLst = append(sLst, operation.RandomScalar())
			var temp operation.Point
			_, err := temp.FromBytesS(rawPoint)
			if err != nil {
				panic(err)
			}
			pLst = append(pLst, &temp)
		}
		p := operation.NewGeneratorPoint()
		p.MultiScalarMult(sLst, pLst)
	},
	"newed-multi-vartime": func(points [][]byte) {
		var sLst []*operation.Scalar
		var pLst []*operation.Point
		for _, rawPoint := range points {
			sLst = append(sLst, operation.RandomScalar())
			var temp operation.Point
			_, err := temp.FromBytesS(rawPoint)
			if err != nil {
				panic(err)
			}
			pLst = append(pLst, &temp)
		}
		p := operation.NewGeneratorPoint()
		p.VarTimeMultiScalarMult(sLst, pLst)
	},
}

type fnRandomAddPedersen = func([]byte, []byte)

var pedAdds = map[string]fnRandomAddPedersen{
	"old": func(raw_A, raw_B []byte) {
		sc_a := operation_old.RandomScalar()
		sc_b := operation_old.RandomScalar()
		pA := &operation_old.Point{}
		pA.FromBytesS(raw_A)
		pB := &operation_old.Point{}
		pB.FromBytesS(raw_B)
		(&operation_old.Point{}).AddPedersen(sc_a, pA, sc_b, pB)
	},
	"new": func(raw_A, raw_B []byte) {
		sc_a := operation.RandomScalar()
		sc_b := operation.RandomScalar()
		pA := &operation.Point{}
		pA.FromBytesS(raw_A)
		pB := &operation.Point{}
		pB.FromBytesS(raw_B)
		(&operation.Point{}).AddPedersen(sc_a, pA, sc_b, pB)
	},
}

func BenchmarkBPProve(b *testing.B) {
	benchmarks := []struct {
		prover     string
		numOutputs int
	}{
		{"Go&old-curve-impl", 1},
		{"Go&old-curve-impl", 2},
		{"Go&old-curve-impl", 4},
		{"Go&old-curve-impl", 8},
		{"Go&old-curve-impl", 16},
		{"Go&new-curve-impl", 1},
		{"Go&new-curve-impl", 2},
		{"Go&new-curve-impl", 4},
		{"Go&new-curve-impl", 8},
		{"Go&new-curve-impl", 16},
		{"Dalek-cgo", 1},
		{"Dalek-cgo", 2},
		{"Dalek-cgo", 4},
		{"Dalek-cgo", 8},
		{"Dalek-cgo", 16},
	}

	for _, bm := range benchmarks {
		// prepare prover inputs
		values := make([]uint64, bm.numOutputs)
		rands := make([]*operation.Scalar, bm.numOutputs)
		rands2 := make([]*operation_old.Scalar, bm.numOutputs)
		for i := range values {
			values[i] = uint64(rand.Uint64())
			rands[i] = operation.RandomScalar()
			rands2[i] = (&operation_old.Scalar{}).FromBytesS(rands[i].ToBytesS())
		}

		b.ResetTimer()
		b.Run(fmt.Sprintf("%s proving %d outputs", bm.prover, bm.numOutputs), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				provers[bm.prover](values, rands, rands2)
			}
		})
	}
}

func BenchmarkBPVerify(b *testing.B) {
	benchmarks := []struct {
		prover     string
		numOutputs int
	}{
		{"Go&old-curve-impl", 1},
		{"Go&old-curve-impl", 2},
		{"Go&old-curve-impl", 4},
		{"Go&old-curve-impl", 8},
		{"Go&old-curve-impl", 16},
		{"Go&old-curve-impl", 32},
		{"Go&new-curve-impl", 1},
		{"Go&new-curve-impl", 2},
		{"Go&new-curve-impl", 4},
		{"Go&new-curve-impl", 8},
		{"Go&new-curve-impl", 16},
		{"Go&new-curve-impl", 32},
	}

	for _, bm := range benchmarks {
		// prepare prover inputs
		values := make([]uint64, bm.numOutputs)
		rands := make([]*operation.Scalar, bm.numOutputs)
		rands2 := make([]*operation_old.Scalar, bm.numOutputs)
		for i := range values {
			values[i] = uint64(rand.Uint64())
			rands[i] = operation.RandomScalar()
			rands2[i] = (&operation_old.Scalar{}).FromBytesS(rands[i].ToBytesS())
		}
		provers["Go&old-curve-impl"](values, rands, rands2)
		provers["Go&new-curve-impl"](values, rands, rands2)

		b.ResetTimer()
		b.Run(fmt.Sprintf("%s verify %d outputs", bm.prover, bm.numOutputs), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pverifiers[bm.prover]()
			}
		})
	}
}

func BenchmarkCurvePointMult(b *testing.B) {
	benchmarks := []struct {
		curvelib string
	}{
		{"dero-base"},
		{"newed-base"},
		{"dero-point"},
		{"newed-point"},
		{"legacy-map-to-point"},
	}

	for _, bm := range benchmarks {
		b.ResetTimer()
		b.Run(fmt.Sprintf("%s scalar-mult", bm.curvelib), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pointMults[bm.curvelib]()
			}
		})
	}
}

func BenchmarkMultiScalarMult(b *testing.B) {
	benchmarks := []struct {
		curvelib  string
		numPoints int
	}{
		{"dero-multi", 4},
		{"dero-multi", 8},
		{"dero-multi", 16},
		{"newed-multi", 2},
		{"newed-multi", 4},
		{"newed-multi", 8},
		{"newed-multi", 16},
		{"newed-multi", 32},
		{"newed-multi", 64},
		// {"newed-multi", 128},
		// {"newed-multi", 256},
		// {"newed-multi", 512},
		// {"newed-multi", 1024},
		// {"newed-multi", 2048},
		// {"newed-multi", 4096},

		{"newed-multi-vartime", 4},
	}

	for _, bm := range benchmarks {
		pointsRaw := make([][]byte, bm.numPoints)
		for i := 0; i < bm.numPoints; i++ {
			pointsRaw[i] = operation.RandomPoint().ToBytesS()
		}
		b.ResetTimer()
		b.Run(fmt.Sprintf("%s multi-scalar-mult-%d", bm.curvelib, bm.numPoints), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				multiScalarMults[bm.curvelib](pointsRaw)
			}
		})
	}
}

func BenchmarkAddPedersen(b *testing.B) {
	benchmarks := []struct {
		curvelib string
	}{
		{"old"},
		{"new"},
	}

	for _, bm := range benchmarks {
		pointsRaw := make([][]byte, 2)
		for i := 0; i < 2; i++ {
			pointsRaw[i] = operation.RandomPoint().ToBytesS()
		}
		b.ResetTimer()
		b.Run(fmt.Sprintf("%s add-pedersen", bm.curvelib), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pedAdds[bm.curvelib](pointsRaw[0], pointsRaw[1])
			}
		})
	}
}

func BenchmarkPrecomputeForAddPedersen(b *testing.B) {
	benchmarks := []struct {
		curvelib string
	}{
		{"old"},
	}

	for _, bm := range benchmarks {
		b.ResetTimer()
		b.Run(fmt.Sprintf("%s add-pedersen", bm.curvelib), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				var cachedPoint [8]C25519.CachedGroupElement
				p := operation_old.RandomPoint()
				var tempGe C25519.ExtendedGroupElement
				temp := p.GetKey()
				tempGe.FromBytes(&temp)
				C25519.GePrecompute(&cachedPoint, &tempGe)
			}
		})
	}
}

func TestProveVerifyRangeProof(t *testing.T) {
	numOutputs := int(rand.Uint64()%16) + 1
	values := make([]uint64, numOutputs)
	rands := make([]*operation.Scalar, numOutputs)
	rands2 := make([]*operation_old.Scalar, numOutputs)
	for i := range values {
		values[i] = uint64(rand.Uint64())
		rands[i] = operation.RandomScalar()
		rands2[i] = (&operation_old.Scalar{}).FromBytesS(rands[i].ToBytesS())
	}
	// old prover + new verifier
	{
		wit := new(bulletproofs_old.AggregatedRangeWitness)
		wit.Set(values, rands2)
		proof, err := wit.Prove()
		Nil(t, err)
		valid, err := proof.VerifyFaster()
		Nil(t, err)
		True(t, valid)

		proofAgain := &AggregatedRangeProof{}

		// fmt.Printf("proof 1 %x\n", proof.Bytes())
		err = proofAgain.SetBytes(proof.Bytes())
		// fmt.Printf("proof 2 %x\n", proofAgain.Bytes())
		Nil(t, err)
		valid, err = proofAgain.Verify()
		Nil(t, err)
		True(t, valid)
		valid, err = proofAgain.VerifyFaster()
		Nil(t, err)
		True(t, valid)
	}

	// new prover + old verifier
	{
		wit := new(AggregatedRangeWitness)
		wit.Set(values, rands)
		proof, err := wit.Prove()
		Nil(t, err)
		valid, err := proof.Verify()
		Nil(t, err)
		True(t, valid)

		proofAgain := &bulletproofs_old.AggregatedRangeProof{}
		// fmt.Printf("proof 1 %x\n", proof.Bytes())
		err = proofAgain.SetBytes(proof.Bytes())
		// fmt.Printf("proof 2 %x\n", proofAgain.Bytes())
		Nil(t, err)
		valid, err = proofAgain.Verify()
		Nil(t, err)
		True(t, valid)
		valid, err = proofAgain.VerifyFaster()
		Nil(t, err)
		True(t, valid)
	}
}
