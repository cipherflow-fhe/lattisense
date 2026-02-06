package testacc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/utils"
)

var (
	gpu_base_path  = "/acc_test/integrate/gpu_tests"
)

func testString(opname string, p interface{}, lvl int) string {
	var res string
	switch p.(type) {
	case bfv.Parameters:
		res = fmt.Sprintf("BFV/%s/lvl=%d", opname, lvl)
	case ckks.Parameters:
		res = fmt.Sprintf("CKKS/%s/lvl=%d", opname, lvl)
	}

	return res
}

type testBfvContext struct {
	n_op        int
	params      bfv.Parameters
	ringQ       *ring.Ring
	ringT       *ring.Ring
	prng        utils.PRNG
	uSampler    *ring.UniformSampler
	encoder     bfv.Encoder
	kgen        rlwe.KeyGenerator
	sk          *rlwe.SecretKey
	pk          *rlwe.PublicKey
	encryptorPk bfv.Encryptor
	encryptorSk bfv.Encryptor
	decryptor   bfv.Decryptor
	testLevel   []int
}

func genTestBfvParams(paramsLiteral bfv.ParametersLiteral) (tc *testBfvContext, err error) {
	tc = new(testBfvContext)
	tc.n_op = 4

	tc.params, _ = bfv.NewParametersFromLiteral(paramsLiteral)

	if tc.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	tc.ringQ = tc.params.RingQ()
	tc.ringT = tc.params.RingT()

	tc.uSampler = ring.NewUniformSampler(tc.prng, tc.ringT)
	tc.kgen = bfv.NewKeyGenerator(tc.params)
	tc.sk, tc.pk = tc.kgen.GenKeyPair()

	tc.encoder = bfv.NewEncoder(tc.params)
	tc.encryptorPk = bfv.NewEncryptor(tc.params, tc.pk)
	tc.encryptorSk = bfv.NewEncryptor(tc.params, tc.sk)
	tc.decryptor = bfv.NewDecryptor(tc.params, tc.sk)

	for i := 1; i <= tc.params.MaxLevel(); i++ {
		tc.testLevel = append(tc.testLevel, i)
	}
	return
}

func newTestVectorsRingQLvl(level int, tc *testBfvContext, pt_type string, encryptor bfv.Encryptor, t *testing.T) (coeffs []*ring.Poly, plaintext []bfv.Operand, ciphertext []*bfv.Ciphertext) {
	for i := 0; i < tc.n_op; i++ {
		coeffs_i := tc.uSampler.ReadNew()
		for j := range coeffs_i.Coeffs[0] {
			coeffs_i.Coeffs[0][j] = uint64(j)
		}
		var plaintext_i bfv.Operand
		switch pt_type {
		case "pt":
			pt := bfv.NewPlaintextLvl(tc.params, level)
			tc.encoder.Encode(coeffs_i.Coeffs[0], pt)
			plaintext_i = pt
		case "pt_rt":
			pt := bfv.NewPlaintextRingT(tc.params)
			tc.encoder.EncodeRingT(coeffs_i.Coeffs[0], pt)
			plaintext_i = pt
		case "pt_mul":
			pt := bfv.NewPlaintextMulLvl(tc.params, level)
			tc.encoder.EncodeMul(coeffs_i.Coeffs[0], pt)
			plaintext_i = pt
		default:
			panic(fmt.Errorf("invalid encode type: %s", pt_type))
		}

		coeffs = append(coeffs, coeffs_i)
		plaintext = append(plaintext, plaintext_i)
		if encryptor != nil {
			pt := bfv.NewPlaintextLvl(tc.params, level)
			tc.encoder.Encode(coeffs_i.Coeffs[0], pt)
			ciphertext_i := encryptor.EncryptNew(pt)
			ciphertext = append(ciphertext, ciphertext_i)
		}
	}

	return coeffs, plaintext, ciphertext
}

func verifyTestBfvVectors(tc *testBfvContext, coeffs *ring.Poly, element bfv.Operand, t *testing.T) {
	var coeffsTest []uint64
	switch el := element.(type) {
	case *bfv.Plaintext, *bfv.PlaintextMul, *bfv.PlaintextRingT:
		coeffsTest = tc.encoder.DecodeUintNew(el)
	case *bfv.Ciphertext:
		coeffsTest = tc.encoder.DecodeUintNew(tc.decryptor.DecryptNew(el))
	default:
		t.Error("invalid test object to verify")
	}

	valuesTest := coeffsTest
	valuesWant := coeffs.Coeffs[0]
	fmt.Printf("ValuesTest: %d %d %d %d...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant: %d %d %d %d...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])

	if !utils.EqualSliceUint64(coeffs.Coeffs[0], coeffsTest) {
		fmt.Println()
	}

	require.True(t, utils.EqualSliceUint64(coeffs.Coeffs[0], coeffsTest))
}

type testCkksContext struct {
	n_op        int
	minPrec     float64
	params      ckks.Parameters
	ringQ       *ring.Ring
	ringP       *ring.Ring
	prng        utils.PRNG
	encoder     ckks.Encoder
	kgen        rlwe.KeyGenerator
	sk          *rlwe.SecretKey
	pk          *rlwe.PublicKey
	encryptorPk ckks.Encryptor
	encryptorSk ckks.Encryptor
	decryptor   ckks.Decryptor
	testLevel   []int
}

func genTestCkksParams(paramsLiteral ckks.ParametersLiteral) (tc *testCkksContext, err error) {
	tc = new(testCkksContext)
	tc.n_op = 4
	tc.minPrec = 10.0

	tc.params, _ = ckks.NewParametersFromLiteral(paramsLiteral)

	tc.kgen = ckks.NewKeyGenerator(tc.params)
	tc.sk, tc.pk = tc.kgen.GenKeyPair()

	tc.ringQ = tc.params.RingQ()
	tc.ringP = tc.params.RingP()

	if tc.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	tc.encoder = ckks.NewEncoder(tc.params)
	tc.encryptorPk = ckks.NewEncryptor(tc.params, tc.pk)
	tc.encryptorSk = ckks.NewEncryptor(tc.params, tc.sk)
	tc.decryptor = ckks.NewDecryptor(tc.params, tc.sk)

	for i := 1; i <= tc.params.MaxLevel(); i++ {
		tc.testLevel = append(tc.testLevel, i)
	}
	return tc, nil
}

func verifyTestCkksVectors(tc *testCkksContext, valuesWant []complex128, element interface{}, logSlots int, bound float64, t *testing.T) {
	precStats := ckks.GetPrecisionStats(tc.params, tc.encoder, tc.decryptor, valuesWant, element, logSlots, bound)
	require.GreaterOrEqual(t, precStats.MeanPrecision.Real, tc.minPrec)
	require.GreaterOrEqual(t, precStats.MeanPrecision.Imag, tc.minPrec)
}

func newTestVectors(level int, scale float64, tc *testCkksContext, encryptor ckks.Encryptor, a, b complex128) (values [][]complex128, plaintext []*ckks.Plaintext, ciphertext []*ckks.Ciphertext) {
	logSlots := tc.params.LogSlots()
	values = make([][]complex128, tc.n_op)
	plaintext = make([]*ckks.Plaintext, tc.n_op)
	ciphertext = make([]*ckks.Ciphertext, tc.n_op)

	for i := 0; i < tc.n_op; i++ {
		values[i] = make([]complex128, 1<<logSlots)
		for j := 0; j < 1<<logSlots; j++ {
			values[i][j] = complex(utils.RandFloat64(real(a), real(b)), utils.RandFloat64(imag(a), imag(b)))
		}

		plaintext[i] = tc.encoder.EncodeNew(values[i], level, scale, logSlots)

		if encryptor != nil {
			ciphertext[i] = encryptor.EncryptNew(plaintext[i])
		}
	}

	return values, plaintext, ciphertext
}

func newTest2dVectors(row int, col int, level int, scale float64, tc *testCkksContext, encryptor ckks.Encryptor, a, b complex128) (values [][][]complex128, plaintext [][]*ckks.Plaintext, ciphertext [][]*ckks.Ciphertext) {
	logSlots := tc.params.LogSlots()
	values = make([][][]complex128, row)
	plaintext = make([][]*ckks.Plaintext, row)
	ciphertext = make([][]*ckks.Ciphertext, row)

	for i := 0; i < row; i++ {
		values[i] = make([][]complex128, col)
		plaintext[i] = make([]*ckks.Plaintext, col)
		ciphertext[i] = make([]*ckks.Ciphertext, col)
		for j := 0; j < col; j++ {
			values[i][j] = make([]complex128, 1<<logSlots)
			for k := 0; k < 1<<logSlots; k++ {
				// values[i][j][k] = float64(utils.RandFloat64(real(a), real(b)))
				values[i][j][k] = complex(utils.RandFloat64(real(a), real(b)), utils.RandFloat64(imag(a), imag(b)))
			}
			plaintext[i][j] = tc.encoder.EncodeNew(values[i][j], level, scale, logSlots)

			if encryptor != nil {
				ciphertext[i][j] = encryptor.EncryptNew(plaintext[i][j])
			}
		}
	}

	return values, plaintext, ciphertext
}

func newTest3dVectors(f int, dim0 int, dim1 int, dim2 int, level int, scale float64, tc *testCkksContext, encryptor ckks.Encryptor, a, b complex128) (values [][][][]complex128, plaintext [][][]*ckks.Plaintext, ciphertext [][][]*ckks.Ciphertext) {
	logSlots := tc.params.LogSlots()
	values = make([][][][]complex128, dim0)
	plaintext = make([][][]*ckks.Plaintext, dim0)
	ciphertext = make([][][]*ckks.Ciphertext, dim0)

	for i := 0; i < dim0; i++ {
		values[i] = make([][][]complex128, dim1)
		plaintext[i] = make([][]*ckks.Plaintext, dim1)
		ciphertext[i] = make([][]*ckks.Ciphertext, dim1)
		for j := 0; j < dim1; j++ {
			values[i][j] = make([][]complex128, dim2)
			plaintext[i][j] = make([]*ckks.Plaintext, dim2)
			ciphertext[i][j] = make([]*ckks.Ciphertext, dim2)
			for k := 0; k < dim2; k++ {
				values[i][j][k] = make([]complex128, 1<<logSlots)
				for l := 0; l < 1<<logSlots; l++ {
					if f == 0 {
						values[i][j][k][l] = complex(utils.RandFloat64(real(a), real(b)), utils.RandFloat64(imag(a), imag(b)))
					} else {
						values[i][j][k][l] = complex(utils.RandFloat64(real(a), real(b)), utils.RandFloat64(imag(a), imag(b)))
					}
					// values[i][j][k][l] = float64(utils.RandFloat64(real(a), real(b)))
				}
				plaintext[i][j][k] = tc.encoder.EncodeNew(values[i][j][k], level, scale, logSlots)

				if encryptor != nil {
					ciphertext[i][j][k] = encryptor.EncryptNew(plaintext[i][j][k])
				}
			}
		}
	}

	return values, plaintext, ciphertext
}

func newTest4dVectors(dim0 int, dim1 int, dim2 int, dim3 int, level int, scale float64, tc *testCkksContext, encryptor ckks.Encryptor, a, b complex128) (values [][][][][]complex128, plaintext [][][][]*ckks.Plaintext, ciphertext [][][][]*ckks.Ciphertext) {
	logSlots := tc.params.LogSlots()
	values = make([][][][][]complex128, dim0)
	plaintext = make([][][][]*ckks.Plaintext, dim0)
	ciphertext = make([][][][]*ckks.Ciphertext, dim0)

	for i := 0; i < dim0; i++ {
		values[i] = make([][][][]complex128, dim1)
		plaintext[i] = make([][][]*ckks.Plaintext, dim1)
		ciphertext[i] = make([][][]*ckks.Ciphertext, dim1)
		for j := 0; j < dim1; j++ {
			values[i][j] = make([][][]complex128, dim2)
			plaintext[i][j] = make([][]*ckks.Plaintext, dim2)
			ciphertext[i][j] = make([][]*ckks.Ciphertext, dim2)
			for k := 0; k < dim2; k++ {
				values[i][j][k] = make([][]complex128, dim3)
				plaintext[i][j][k] = make([]*ckks.Plaintext, dim3)
				ciphertext[i][j][k] = make([]*ckks.Ciphertext, dim3)
				for l := 0; l < dim3; l++ {
					values[i][j][k][l] = make([]complex128, 1<<logSlots)
					for m := 0; m < 1<<logSlots; m++ {
						values[i][j][k][l][m] = complex(utils.RandFloat64(real(a), real(b)), utils.RandFloat64(imag(a), imag(b)))
					}
					plaintext[i][j][k][l] = tc.encoder.EncodeNew(values[i][j][k][l], level, scale, logSlots)

					if encryptor != nil {
						ciphertext[i][j][k][l] = encryptor.EncryptNew(plaintext[i][j][k][l])
					}
				}
			}
		}
	}

	return values, plaintext, ciphertext
}
