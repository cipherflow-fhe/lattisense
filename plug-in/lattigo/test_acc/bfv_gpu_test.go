package testacc

import (
	"fmt"
	"lattigo_acc/acc"

	"runtime"
	"testing"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/utils"
)

var (
	TestBfvGpuParamLiterals = []bfv.ParametersLiteral{bfv.PN14QP438}
)

func TestBfvGpuAcc(t *testing.T) {
	var err error

	for _, literal := range TestBfvGpuParamLiterals[:] {

		var tc *testBfvContext
		if tc, err = genTestBfvParams(literal); err != nil {
			t.Fatal(err)
		}

		for _, testSet := range []func(tc *testBfvContext, t *testing.T){
			testBfvGpuCtAddPtRt,
			testBfvGpuCtAddPt,
			testBfvGpuCtAddCt,
			testBfvGpuCtMulPtRt,
			testBfvGpuCtMulCtRelin,
			testBfvGpuCtSquareRelin,
			testBfvGpuCtRotateCol,
			testBfvGpuCtRotateRow,
			testBfvGpuCtRescale,
		} {
			testSet(tc, t)
			runtime.GC()
		}

	}

}

func testBfvGpuCtAddPtRt(tc *testBfvContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtAddPtRt/op1=Ciphertext/op2=PlaintextRt", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)
			values2, plaintext2, _ := newTestVectorsRingQLvl(lvl, tc, "pt_rt", tc.encryptorPk, t)

			ciphertext := make([]*bfv.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = bfv.NewCiphertextLvl(tc.params, 1, lvl)
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("in_y_list", plaintext2),
				acc.NewGoVectorArgument("out_z_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/BFV_%d_cap_ringt/level_%d", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				tc.ringT.Add(values1[i], values2[i], values1[i])
				verifyTestBfvVectors(tc, values1[i], ciphertext[i], t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}

func testBfvGpuCtAddPt(tc *testBfvContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtAddPt/op1=Ciphertext/op2=Plaintext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)
			values2, plaintext2, _ := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)

			ciphertext := make([]*bfv.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = bfv.NewCiphertextLvl(tc.params, 1, lvl)
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("in_y_list", plaintext2),
				acc.NewGoVectorArgument("out_z_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/BFV_%d_cap/level_%d", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				tc.ringT.Add(values1[i], values2[i], values1[i])
				verifyTestBfvVectors(tc, values1[i], ciphertext[i], t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}

func testBfvGpuCtAddCt(tc *testBfvContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtAddCt/op1=Ciphertext/op2=Ciphertext", tc.params, lvl), func(t *testing.T) {

			values1, _, ciphertext1 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)
			values2, _, ciphertext2 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)

			ciphertext := make([]*bfv.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = bfv.NewCiphertextLvl(tc.params, 1, lvl)
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("in_y_list", ciphertext2),
				acc.NewGoVectorArgument("out_z_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/BFV_%d_cac/level_%d", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				tc.ringT.Add(values1[i], values2[i], values1[i])
				verifyTestBfvVectors(tc, values1[i], ciphertext[i], t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}

func testBfvGpuCtMulPtRt(tc *testBfvContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtMulPtRt/op1=Ciphertext/op2=PlaintextRt", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)
			values2, plaintext2, _ := newTestVectorsRingQLvl(lvl, tc, "pt_rt", tc.encryptorPk, t)

			ciphertext := make([]*bfv.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = bfv.NewCiphertextLvl(tc.params, 1, lvl)
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("in_y_list", plaintext2),
				acc.NewGoVectorArgument("out_z_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/BFV_%d_cmp_ringt/level_%d", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				tc.ringT.MulCoeffs(values1[i], values2[i], values1[i])
				verifyTestBfvVectors(tc, values1[i], ciphertext[i], t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}

func testBfvGpuCtMulCtRelin(tc *testBfvContext, t *testing.T) {
	rlk := tc.kgen.GenRelinearizationKey(tc.sk, 1)

	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtMulCtRelin/op1=Ciphertext/op2=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)
			values2, _, ciphertext2 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)

			ciphertext := make([]*bfv.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = bfv.NewCiphertextLvl(tc.params, 1, lvl)
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("in_y_list", ciphertext2),
				acc.NewGoVectorArgument("out_z_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/BFV_%d_cmc_relin/level_%d", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, rlk, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				tc.ringT.MulCoeffs(values1[i], values2[i], values1[i])
				verifyTestBfvVectors(tc, values1[i], ciphertext[i], t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}

func testBfvGpuCtRotateCol(tc *testBfvContext, t *testing.T) {
	steps := []int{-900, 20, 400, 2000, 3009}
	glk := tc.kgen.GenRotationKeysForRotations(steps, false, tc.sk)

	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtRotateCol/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)
			ciphertext := make([][]*bfv.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = make([]*bfv.Ciphertext, len(steps))
				for j := range ciphertext[i] {
					ciphertext[i][j] = bfv.NewCiphertextLvl(tc.params, 1, lvl)
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
			project_path := fmt.Sprintf("%s/BFV_%d_advanced_rotate_col/level_%d/steps_%s", gpu_base_path, tc.n_op, lvl, steps_str)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, glk, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				origin := values1[i].Coeffs[0]
				for j, step := range steps {
					values1[i].Coeffs[0] = utils.RotateUint64Slots(origin, step)
					verifyTestBfvVectors(tc, values1[i], ciphertext[i][j], t)
				}
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}

func testBfvGpuCtSquareRelin(tc *testBfvContext, t *testing.T) {
	rlk := tc.kgen.GenRelinearizationKey(tc.sk, 1)

	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtSquareRelin/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)

			ciphertext := make([]*bfv.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = bfv.NewCiphertextLvl(tc.params, 1, lvl)
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("out_z_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/BFV_%d_csqr_relin/level_%d", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, rlk, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				tc.ringT.MulCoeffs(values1[i], values1[i], values1[i])
				verifyTestBfvVectors(tc, values1[i], ciphertext[i], t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}

func testBfvGpuCtRotateRow(tc *testBfvContext, t *testing.T) {
	glk := tc.kgen.GenRotationKeysForRotations([]int{}, true, tc.sk)
	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtRotateRow/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)

			ciphertext := make([]*bfv.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = bfv.NewCiphertextLvl(tc.params, 1, lvl)
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("arg_x", ciphertext1),
				acc.NewGoVectorArgument("arg_y", ciphertext),
			}
			project_path := fmt.Sprintf("%s/BFV_%d_rotate_row/level_%d/", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, glk, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				values1[i].Coeffs[0] = append(values1[i].Coeffs[0][tc.params.N()>>1:], values1[i].Coeffs[0][:tc.params.N()>>1]...)
				verifyTestBfvVectors(tc, values1[i], ciphertext[i], t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}

func testBfvGpuCtRescale(tc *testBfvContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("GpuRunner/CtRescale/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)

			ciphertext := make([]*bfv.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = bfv.NewCiphertextLvl(tc.params, 1, lvl-1)
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("out_y_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/BFV_%d_rescale/level_%d", gpu_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskGpu(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < tc.n_op; i++ {
				verifyTestBfvVectors(tc, values1[i], ciphertext[i], t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}
