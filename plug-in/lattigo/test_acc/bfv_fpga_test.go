/*
 * Copyright (c) 2025-2026 CipherFlow (Shenzhen) Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

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
	TestBfvFpgaParamLiterals = []bfv.ParametersLiteral{acc.BfvFpgaParametersLiteral}
	bfv_fpga_base_path = fpga_base_path + "/bfv_param_fpga_n8192_t1b4001"
)

func TestBfvFpgaAcc(t *testing.T) {
	acc.Sigsetup()
	var err error
	fpgaDevice := acc.GetFpgaDevice()
	if err = fpgaDevice.Init(); err != nil {
		t.Fatal(err)
	}
	defer fpgaDevice.Free()

	for _, literal := range TestBfvFpgaParamLiterals[:] {

		var tc *testBfvContext
		if tc, err = genTestBfvParams(literal); err != nil {
			t.Fatal(err)
		}

		for _, testSet := range []func(tc *testBfvContext, t *testing.T){
			testBfvFpgaCtAddPt,
			testBfvFpgaCtAddCt,
			testBfvFpgaCtMulPtRt,
			testBfvFpgaCtMulPt,
			testBfvFpgaCtMulPtMul,
			testBfvFpgaCtMulCtRelin,
			testBfvFpgaCtSquareRelin,
			testBfvFpgaCtRotateCol,
			testBfvFpgaCtRotateRow,
			testBfvFpgaCtRescale,
		} {
			testSet(tc, t)
			runtime.GC()
		}

	}
}

func testBfvFpgaCtAddPt(tc *testBfvContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtAddPt/op1=Ciphertext/op2=Plaintext", tc.params, lvl), func(t *testing.T) {

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
			project_path := fmt.Sprintf("%s/BFV_%d_cap/level_%d", bfv_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testBfvFpgaCtAddCt(tc *testBfvContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtAddCt/op1=Ciphertext/op2=Ciphertext", tc.params, lvl), func(t *testing.T) {

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
			project_path := fmt.Sprintf("%s/BFV_%d_cac/level_%d", bfv_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testBfvFpgaCtMulPtRt(tc *testBfvContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtMulPtRt/op1=Ciphertext/op2=PlaintextRt", tc.params, lvl), func(t *testing.T) {
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
			project_path := fmt.Sprintf("%s/BFV_%d_cmp_ringt/level_%d", bfv_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testBfvFpgaCtMulPt(tc *testBfvContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtMulPt/op1=Ciphertext/op2=Plaintext", tc.params, lvl), func(t *testing.T) {
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
			project_path := fmt.Sprintf("%s/BFV_%d_cmp/level_%d", bfv_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testBfvFpgaCtMulPtMul(tc *testBfvContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtMulPtMul/op1=Ciphertext/op2=PlaintextMul", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)
			values2, plaintext2, _ := newTestVectorsRingQLvl(lvl, tc, "pt_mul", tc.encryptorPk, t)

			ciphertext := make([]*bfv.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = bfv.NewCiphertextLvl(tc.params, 1, lvl)
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("in_y_list", plaintext2),
				acc.NewGoVectorArgument("out_z_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/BFV_%d_cmp_mul/level_%d", bfv_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testBfvFpgaCtMulCtRelin(tc *testBfvContext, t *testing.T) {
	rlk := tc.kgen.GenRelinearizationKey(tc.sk, 1)

	for _, lvl := range tc.testLevel {
		if lvl <= 1 {
			continue
		}

		t.Run(testString("FpgaRunner/CtMulCtRelin/op1=Ciphertext/op2=Ciphertext", tc.params, lvl), func(t *testing.T) {
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
			project_path := fmt.Sprintf("%s/BFV_%d_cmc_relin/level_%d", bfv_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testBfvFpgaCtSquareRelin(tc *testBfvContext, t *testing.T) {
	rlk := tc.kgen.GenRelinearizationKey(tc.sk, 1)

	for _, lvl := range tc.testLevel {
		if lvl <= 1 {
			continue
		}

		t.Run(testString("FpgaRunner/CtSquareRelin/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)

			ciphertext := make([]*bfv.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = bfv.NewCiphertextLvl(tc.params, 1, lvl)
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("out_z_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/BFV_%d_csqr_relin/level_%d", bfv_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testBfvFpgaCtRotateCol(tc *testBfvContext, t *testing.T) {
	steps := []int{-900, 20, 400, 2000, 3009}
	glk := tc.kgen.GenRotationKeysForRotations(steps, false, tc.sk)

	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtRotateCol/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
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
			steps_str += ""
			project_path := fmt.Sprintf("%s/BFV_%d_advanced_rotate_col/level_%d/steps_%s", bfv_fpga_base_path, tc.n_op, lvl, steps_str)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testBfvFpgaCtRotateRow(tc *testBfvContext, t *testing.T) {
	glk := tc.kgen.GenRotationKeysForRotations([]int{}, true, tc.sk)

	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtRotateRow/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)
			ciphertext := make([]*bfv.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = bfv.NewCiphertextLvl(tc.params, 1, lvl)
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("arg_x", ciphertext1),
				acc.NewGoVectorArgument("arg_y", ciphertext),
			}

			project_path := fmt.Sprintf("%s/BFV_%d_rotate_row/level_%d/", bfv_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testBfvFpgaCtRescale(tc *testBfvContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtRescale/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectorsRingQLvl(lvl, tc, "pt", tc.encryptorPk, t)

			ciphertext := make([]*bfv.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = bfv.NewCiphertextLvl(tc.params, 1, lvl-1)
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("out_y_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/BFV_%d_rescale/level_%d", bfv_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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
