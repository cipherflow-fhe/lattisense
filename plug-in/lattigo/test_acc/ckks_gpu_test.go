package testacc

import (
	"fmt"
	"lattigo_acc/acc"
	"runtime"
	"testing"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/utils"
)

var (
	TestCkksGpuParamLiterals = []ckks.ParametersLiteral{ckks.PN14QP438}
)

func TestCkksGpuAcc(t *testing.T) {
	var err error

	for _, literal := range TestCkksGpuParamLiterals[:] {

		var tc *testCkksContext
		if tc, err = genTestCkksParams(literal); err != nil {
			t.Fatal(err)
		}

		for _, testSet := range []func(tc *testCkksContext, t *testing.T){
			testCkksGpuCtAddPt,
			testCkksGpuCtAddCt,
			testCkksGpuCtMulPt,
			testCkksGpuCtMulCtRelin,
			testCkksGpuCtSquareRelin,
			testCkksGpuCtRotateCol,
			testCkksGpuCtRotateRow,
			testCkksGpuCtRescale,
			testCkksGpuCtDropLevel,
		} {
			testSet(tc, t)
			runtime.GC()
		}
	}
}

func testCkksGpuCtAddPt(tc *testCkksContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtAddPt/op1=Ciphertext/op2=Plaintext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))
			values2, plaintext2, _ := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertext := make([]*ckks.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = ckks.NewCiphertext(tc.params, 1, lvl, tc.params.DefaultScale())
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("in_y_list", plaintext2),
				acc.NewGoVectorArgument("out_z_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/CKKS_%d_cap/level_%d", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				for j := range values1[i] {
					values1[i][j] += values2[i][j]
				}
				verifyTestCkksVectors(tc, values1[i], ciphertext[i], tc.params.LogSlots(), 0, t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testCkksGpuCtAddCt(tc *testCkksContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtAddCt/op1=Ciphertext/op2=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))
			values2, _, ciphertext2 := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertext := make([]*ckks.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = ckks.NewCiphertext(tc.params, 1, lvl, tc.params.DefaultScale())
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("in_y_list", ciphertext2),
				acc.NewGoVectorArgument("out_z_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/CKKS_%d_cac/level_%d", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				for j := range values1[i] {
					values1[i][j] += values2[i][j]
				}
				verifyTestCkksVectors(tc, values1[i], ciphertext[i], tc.params.LogSlots(), 0, t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testCkksGpuCtMulPt(tc *testCkksContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtMulPt/op1=Ciphertext/op2=Plaintext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))
			values2, plaintext2, _ := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertext := make([]*ckks.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = ckks.NewCiphertext(tc.params, 1, lvl, tc.params.DefaultScale()*tc.params.DefaultScale())
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("in_y_list", plaintext2),
				acc.NewGoVectorArgument("out_z_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/CKKS_%d_cmp/level_%d", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				for j := range values1[i] {
					values1[i][j] *= values2[i][j]
				}
				verifyTestCkksVectors(tc, values1[i], ciphertext[i], tc.params.LogSlots(), 0, t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testCkksGpuCtMulCtRelin(tc *testCkksContext, t *testing.T) {
	rlk := tc.kgen.GenRelinearizationKey(tc.sk, 1)

	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtMulCtRelin/op1=Ciphertext/op2=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))
			values2, _, ciphertext2 := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertext := make([]*ckks.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = ckks.NewCiphertext(tc.params, 1, lvl, tc.params.DefaultScale()*tc.params.DefaultScale())
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("in_y_list", ciphertext2),
				acc.NewGoVectorArgument("out_z_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/CKKS_%d_cmc_relin/level_%d", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, rlk, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				for j := range values1[i] {
					values1[i][j] *= values2[i][j]
				}
				verifyTestCkksVectors(tc, values1[i], ciphertext[i], tc.params.LogSlots(), 0, t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testCkksGpuCtSquareRelin(tc *testCkksContext, t *testing.T) {
	rlk := tc.kgen.GenRelinearizationKey(tc.sk, 1)

	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtSquareRelin/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertext := make([]*ckks.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = ckks.NewCiphertext(tc.params, 1, lvl, tc.params.DefaultScale()*tc.params.DefaultScale())
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("out_z_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/CKKS_%d_csqr_relin/level_%d", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, rlk, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				for j := range values1[i] {
					values1[i][j] *= values1[i][j]
				}
				verifyTestCkksVectors(tc, values1[i], ciphertext[i], tc.params.LogSlots(), 0, t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testCkksGpuCtRotateCol(tc *testCkksContext, t *testing.T) {
	steps := []int{-500, 20, 200, 2000, 4000}
	glk := tc.kgen.GenRotationKeysForRotations(steps, false, tc.sk)

	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtRotateCol/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertext := make([][]*ckks.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = make([]*ckks.Ciphertext, len(steps))
				for j := range ciphertext[i] {
					ciphertext[i][j] = ckks.NewCiphertext(tc.params, 1, lvl, tc.params.DefaultScale())
				}
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("arg_x", ciphertext1),
				acc.NewGoVectorArgument("arg_y", ciphertext),
			}

			steps_str := ""
			for _, step := range steps {
				steps_str += fmt.Sprintf("%d", step)
				if step != steps[len(steps)-1] {
					steps_str += "_"
				}
			}
			project_path := fmt.Sprintf("%s/CKKS_%d_advanced_rotate_col/level_%d/steps_%s", gpu_base_path, tc.n_op, lvl, steps_str)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, glk, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				origin := values1[i]
				for j, step := range steps {
					values1[i] = utils.RotateComplex128Slice(origin, step)
					verifyTestCkksVectors(tc, values1[i], ciphertext[i][j], tc.params.LogSlots(), 0, t)
				}
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testCkksGpuCtRotateRow(tc *testCkksContext, t *testing.T) {
	glk := tc.kgen.GenRotationKeysForRotations([]int{}, true, tc.sk)

	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtRotateRow/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertext := make([]*ckks.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = ckks.NewCiphertext(tc.params, 1, lvl, tc.params.DefaultScale())
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("arg_x", ciphertext1),
				acc.NewGoVectorArgument("arg_y", ciphertext),
			}

			project_path := fmt.Sprintf("%s/CKKS_%d_rotate_row/level_%d", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, glk, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				for j := range values1[i] {
					values1[i][j] = complex(real(values1[i][j]), -imag(values1[i][j]))
				}
				verifyTestCkksVectors(tc, values1[i], ciphertext[i], tc.params.LogSlots(), 0, t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testCkksGpuCtRescale(tc *testCkksContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtRescale/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectors(lvl, tc.params.DefaultScale()*float64(tc.params.Q()[lvl]), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertext := make([]*ckks.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = ckks.NewCiphertext(tc.params, 1, lvl-1, tc.params.DefaultScale())
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("out_y_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/CKKS_%d_rescale/level_%d", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				verifyTestCkksVectors(tc, values1[i], ciphertext[i], tc.params.LogSlots(), 0, t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testCkksGpuCtDropLevel(tc *testCkksContext, t *testing.T) {
	drop_lvl := 2
	for _, lvl := range tc.testLevel {
		if lvl < drop_lvl {
			continue
		}

		t.Run(testString("GpuRunner/CtDropLevel/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertext := make([]*ckks.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = ckks.NewCiphertext(tc.params, 1, lvl-drop_lvl, tc.params.DefaultScale())
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("out_y_list", ciphertext),
			}

			project_path := fmt.Sprintf("%s/CKKS_%d_drop_level/level_%d/drop_%d", gpu_base_path, tc.n_op, lvl, drop_lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				verifyTestCkksVectors(tc, values1[i], ciphertext[i], tc.params.LogSlots(), 0, t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}
