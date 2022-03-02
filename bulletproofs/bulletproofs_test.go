package bulletproofs

import(
	"fmt"
	"math/rand"
	"testing"
	crypto_rand "crypto/rand"

	bulletproofs_old "github.com/incognitochain/incognito-chain/privacy/privacy_v2/bulletproofs"
	operation_old "github.com/incognitochain/incognito-chain/privacy/operation"
	"github.com/dat-incognito-org/newbp/operation"
)

type fnProve = func(values []uint64, rands []*operation.Scalar, rands2 []*operation_old.Scalar)
var provers = map[string]fnProve{
    "Go&old-curve-impl": func(values []uint64, rands []*operation.Scalar, rands2 []*operation_old.Scalar) {
        wit := new(bulletproofs_old.AggregatedRangeWitness)
        wit.Set(values, rands2)
        wit.Prove()
    },
    "Go&new-curve-impl": func(values []uint64, rands []*operation.Scalar, rands2 []*operation_old.Scalar) {
        wit := new(AggregatedRangeWitness)
        wit.Set(values, rands)
        wit.Prove()
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

type fnRandomScalarMult = func()
var pointMults = map[string]fnRandomScalarMult {
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
var multiScalarMults = map[string]fnRandomMultiScalarMult {
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

type fnRandomAddPedersen = func([] byte, []byte)
var pedAdds = map[string]fnRandomAddPedersen {
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
    benchmarks := []struct{
        prover  string
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
        // {"Dalek-cgo", 1},
        // {"Dalek-cgo", 2},
        // {"Dalek-cgo", 4},
        // {"Dalek-cgo", 8},
        // {"Dalek-cgo", 16},
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

func BenchmarkCurvePointMult(b *testing.B) {
    benchmarks := []struct{
        curvelib  string
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
    benchmarks := []struct{
        curvelib  string
        numPoints int
    }{
        {"dero-multi", 4},
        {"dero-multi", 10},
        {"dero-multi", 21},
        {"newed-multi", 4},
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
    benchmarks := []struct{
        curvelib  string
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
