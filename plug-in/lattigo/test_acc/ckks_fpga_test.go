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

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/utils"
)

var (
	TestCkksFpgaParamLiterals = []ckks.ParametersLiteral{acc.CkksFpgaParametersLiteral}
	ckks_fpga_base_path          = fpga_base_path + "/ckks_param_fpga_n8192"
)

func TestCkksFpgaAcc(t *testing.T) {
	acc.Sigsetup()
	var err error
	fpgaDevice := acc.GetFpgaDevice()
	if err = fpgaDevice.Init(); err != nil {
		t.Fatal(err)
	}
	defer fpgaDevice.Free()

	for _, literal := range TestCkksFpgaParamLiterals[:] {

		var tc *testCkksContext
		if tc, err = genTestCkksParams(literal); err != nil {
			t.Fatal(err)
		}

		for _, testSet := range []func(tc *testCkksContext, t *testing.T){
			testCkksFpgaCtAddPt,
			testCkksFpgaCtAddPt2d,
			testCkksFpgaCtAddPt3d,
			testCkksFpgaCtAddCt,
			testCkksFpgaCtMulPt,
			testCkksFpgaCtMulPt3d,
			testCkksFpgaCtMulPt4d,
			testCkksFpgaCtMulCtRelin,
			testCkksFpgaCtMulCtRelin4d,
			testCkksFpgaCtSquareRelin,
			testCkksFpgaCtRotateCol,
			testCkksFpgaCtRotateRow,
			testCkksFpgaCtRescale,
			testCkksFpgaCtDropLevel,
		} {
			testSet(tc, t)
			runtime.GC()
		}

	}
}

func testCkksFpgaCtAddPt(tc *testCkksContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtAddPt/op1=Ciphertext/op2=Plaintext", tc.params, lvl), func(t *testing.T) {
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
			project_path := fmt.Sprintf("%s/CKKS_%d_cap/level_%d", ckks_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testCkksFpgaCtAddPt2d(tc *testCkksContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtAddPt2d/op1=Ciphertext/op2=Plaintext", tc.params, lvl), func(t *testing.T) {
			row, col := 1, 1
			msgX2d, _, ciphertextX2d := newTest2dVectors(row, col, lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))
			msgY2d, plaintextY2d, _ := newTest2dVectors(row, col, lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertextZ2d := make([][]*ckks.Ciphertext, row)
			for i := 0; i < row; i++ {
				ciphertextZ2d[i] = make([]*ckks.Ciphertext, col)
				for j := 0; j < col; j++ {
					ciphertextZ2d[i][j] = ckks.NewCiphertext(tc.params, 1, lvl, tc.params.DefaultScale())
				}
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("x_ct_2d", ciphertextX2d),
				acc.NewGoVectorArgument("y_pt_2d", plaintextY2d),
				acc.NewGoVectorArgument("z_ct_2d", ciphertextZ2d),
			}
			project_path := fmt.Sprintf("%s/CKKS_cap_row_%d_col_%d/level_%d", ckks_fpga_base_path, row, col, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < row; i++ {
				for j := 0; j < col; j++ {
					for k := range msgX2d[i][j] {
						msgX2d[i][j][k] += msgY2d[i][j][k]
					}
					valuesWant := msgX2d[i][j]
					valuesTest := tc.encoder.Decode(tc.decryptor.DecryptNew(ciphertextZ2d[i][j]), tc.params.LogSlots())
					fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
					fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])
					verifyTestCkksVectors(tc, msgX2d[i][j], ciphertextZ2d[i][j], tc.params.LogSlots(), 0, t)
				}
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}

func testCkksFpgaCtAddPt3d(tc *testCkksContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtAddPt3d/op1=Ciphertext/op2=Plaintext", tc.params, lvl), func(t *testing.T) {
			dim0, dim1, dim2 := 1, 1, 1
			values1, _, ciphertextX3d := newTest3dVectors(0, dim0, dim1, dim2, lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))
			values2, plaintextY3d, _ := newTest3dVectors(1, dim0, dim1, dim2, lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertextZ3d := make([][][]*ckks.Ciphertext, dim0)
			for i := range ciphertextZ3d {
				ciphertextZ3d[i] = make([][]*ckks.Ciphertext, dim1)
				for j := range ciphertextZ3d[i] {
					ciphertextZ3d[i][j] = make([]*ckks.Ciphertext, dim2)
					for k := range ciphertextZ3d[i][j] {
						ciphertextZ3d[i][j][k] = ckks.NewCiphertext(tc.params, 1, lvl, tc.params.DefaultScale())
					}
				}
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("x_ct_3d", ciphertextX3d),
				acc.NewGoVectorArgument("y_pt_3d", plaintextY3d),
				acc.NewGoVectorArgument("z_ct_3d", ciphertextZ3d),
			}
			project_path := fmt.Sprintf("%s/CKKS_cap_3d/level_%d", ckks_fpga_base_path, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < dim0; i++ {
				for j := 0; j < dim1; j++ {
					for k := 0; k < dim2; k++ {
						for l := range values1[i][j][k] {
							values1[i][j][k][l] += values2[i][j][k][l]
						}
						valuesWant := values1[i][j][k]
						valuesTest := tc.encoder.Decode(tc.decryptor.DecryptNew(ciphertextZ3d[i][j][k]), tc.params.LogSlots())
						fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
						fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])
						verifyTestCkksVectors(tc, values1[i][j][k], ciphertextZ3d[i][j][k], tc.params.LogSlots(), 0, t)
					}
				}
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}

func testCkksFpgaCtAddCt(tc *testCkksContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtAddCt/op1=Ciphertext/op2=Ciphertext", tc.params, lvl), func(t *testing.T) {
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
			project_path := fmt.Sprintf("%s/CKKS_%d_cac/level_%d", ckks_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testCkksFpgaCtMulPt(tc *testCkksContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtMulPt/op1=Ciphertext/op2=Plaintext", tc.params, lvl), func(t *testing.T) {
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
			project_path := fmt.Sprintf("%s/CKKS_%d_cmp/level_%d", ckks_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testCkksFpgaCtMulPt3d(tc *testCkksContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtMulPt3d/op1=Ciphertext/op2=Plaintext", tc.params, lvl), func(t *testing.T) {
			dim0, dim1, dim2 := 1, 1, 1
			values1, _, ciphertextX3d := newTest3dVectors(0, dim0, dim1, dim2, lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))
			values2, plaintextY3d, _ := newTest3dVectors(1, dim0, dim1, dim2, lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertextZ3d := make([][][]*ckks.Ciphertext, dim0)
			for i := range ciphertextZ3d {
				ciphertextZ3d[i] = make([][]*ckks.Ciphertext, dim1)
				for j := range ciphertextZ3d[i] {
					ciphertextZ3d[i][j] = make([]*ckks.Ciphertext, dim2)
					for k := range ciphertextZ3d[i][j] {
						ciphertextZ3d[i][j][k] = ckks.NewCiphertext(tc.params, 1, lvl, tc.params.DefaultScale()*tc.params.DefaultScale())
					}
				}
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("x_ct_3d", ciphertextX3d),
				acc.NewGoVectorArgument("y_pt_3d", plaintextY3d),
				acc.NewGoVectorArgument("z_ct_3d", ciphertextZ3d),
			}
			project_path := fmt.Sprintf("%s/CKKS_cmp_3d/level_%d", ckks_fpga_base_path, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < dim0; i++ {
				for j := 0; j < dim1; j++ {
					for k := 0; k < dim2; k++ {
						for l := range values1[i][j][k] {
							values1[i][j][k][l] *= values2[i][j][k][l]
						}
						valuesWant := values1[i][j][k]
						valuesTest := tc.encoder.Decode(tc.decryptor.DecryptNew(ciphertextZ3d[i][j][k]), tc.params.LogSlots())
						fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
						fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])
						verifyTestCkksVectors(tc, values1[i][j][k], ciphertextZ3d[i][j][k], tc.params.LogSlots(), 0, t)
					}
				}
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}

func testCkksFpgaCtMulPt4d(tc *testCkksContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtMulPt4d/op1=Ciphertext/op2=Plaintext", tc.params, lvl), func(t *testing.T) {
			dim0, dim1, dim2, dim3 := 1, 1, 1, 1
			values1, _, ciphertextX4d := newTest4dVectors(dim0, dim1, dim2, dim3, lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))
			values2, plaintextY4d, _ := newTest4dVectors(dim0, dim1, dim2, dim3, lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertextZ4d := make([][][][]*ckks.Ciphertext, dim0)
			for i := range ciphertextZ4d {
				ciphertextZ4d[i] = make([][][]*ckks.Ciphertext, dim1)
				for j := range ciphertextZ4d[i] {
					ciphertextZ4d[i][j] = make([][]*ckks.Ciphertext, dim2)
					for k := range ciphertextZ4d[i][j] {
						ciphertextZ4d[i][j][k] = make([]*ckks.Ciphertext, dim3)
						for l := range ciphertextZ4d[i][j][k] {
							ciphertextZ4d[i][j][k][l] = ckks.NewCiphertext(tc.params, 1, lvl, tc.params.DefaultScale()*tc.params.DefaultScale())
						}
					}
				}
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("x_ct_4d", ciphertextX4d),
				acc.NewGoVectorArgument("y_pt_4d", plaintextY4d),
				acc.NewGoVectorArgument("z_ct_4d", ciphertextZ4d),
			}
			project_path := fmt.Sprintf("%s/CKKS_cmp_4d/level_%d", ckks_fpga_base_path, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, nil, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < dim0; i++ {
				for j := 0; j < dim1; j++ {
					for k := 0; k < dim2; k++ {
						for l := 0; l < dim3; l++ {
							for m := range values1[i][j][k][l] {
								values1[i][j][k][l][m] *= values2[i][j][k][l][m]
							}
							valuesWant := values1[i][j][k][l]
							valuesTest := tc.encoder.Decode(tc.decryptor.DecryptNew(ciphertextZ4d[i][j][k][l]), tc.params.LogSlots())
							fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
							fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])
							verifyTestCkksVectors(tc, values1[i][j][k][l], ciphertextZ4d[i][j][k][l], tc.params.LogSlots(), 0, t)
						}
					}
				}
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}

func testCkksFpgaCtMulCtRelin(tc *testCkksContext, t *testing.T) {
	rlk := tc.kgen.GenRelinearizationKey(tc.sk, 1)

	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtMulCtRelin/op1=Ciphertext/op2=Ciphertext", tc.params, lvl), func(t *testing.T) {
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
			project_path := fmt.Sprintf("%s/CKKS_%d_cmc_relin/level_%d", ckks_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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
				valuesWant := values1[i]
				valuesTest := tc.encoder.Decode(tc.decryptor.DecryptNew(ciphertext[i]), tc.params.LogSlots())
				fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
				fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])
				verifyTestCkksVectors(tc, values1[i], ciphertext[i], tc.params.LogSlots(), 0, t)
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}

func testCkksFpgaCtMulCtRelin4d(tc *testCkksContext, t *testing.T) {
	rlk := tc.kgen.GenRelinearizationKey(tc.sk, 1)

	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtMulCtRelin4d/op1=Ciphertext/op2=Ciphertext", tc.params, lvl), func(t *testing.T) {
			dim0, dim1, dim2, dim3 := 1, 1, 1, 1
			values1, _, ciphertextX4d := newTest4dVectors(dim0, dim1, dim2, dim3, lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))
			values2, _, ciphertextY4d := newTest4dVectors(dim0, dim1, dim2, dim3, lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertextZ4d := make([][][][]*ckks.Ciphertext, dim0)
			for i := range ciphertextZ4d {
				ciphertextZ4d[i] = make([][][]*ckks.Ciphertext, dim1)
				for j := range ciphertextZ4d[i] {
					ciphertextZ4d[i][j] = make([][]*ckks.Ciphertext, dim2)
					for k := range ciphertextZ4d[i][j] {
						ciphertextZ4d[i][j][k] = make([]*ckks.Ciphertext, dim3)
						for l := range ciphertextZ4d[i][j][k] {
							ciphertextZ4d[i][j][k][l] = ckks.NewCiphertext(tc.params, 1, lvl, tc.params.DefaultScale()*tc.params.DefaultScale())
						}
					}
				}
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("x_ct_4d", ciphertextX4d),
				acc.NewGoVectorArgument("y_ct_4d", ciphertextY4d),
				acc.NewGoVectorArgument("z_ct_4d", ciphertextZ4d),
			}
			project_path := fmt.Sprintf("%s/CKKS_cmc_relin_4d/level_%d", ckks_fpga_base_path, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
			if err != nil {
				t.Fatal(err)
			}
			err = project.Run(tc.params, rlk, nil, args)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < dim0; i++ {
				for j := 0; j < dim1; j++ {
					for k := 0; k < dim2; k++ {
						for l := 0; l < dim3; l++ {
							for m := range values1[i][j][k][l] {
								values1[i][j][k][l][m] *= values2[i][j][k][l][m]
							}
							valuesWant := values1[i][j][k][l]
							valuesTest := tc.encoder.Decode(tc.decryptor.DecryptNew(ciphertextZ4d[i][j][k][l]), tc.params.LogSlots())
							fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
							fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])
							verifyTestCkksVectors(tc, values1[i][j][k][l], ciphertextZ4d[i][j][k][l], tc.params.LogSlots(), 0, t)
						}
					}
				}
			}

			err = project.Free()
			if err != nil {
				t.Fatal(err)
			}

		})
	}
}

func testCkksFpgaCtSquareRelin(tc *testCkksContext, t *testing.T) {
	rlk := tc.kgen.GenRelinearizationKey(tc.sk, 1)

	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtSquareRelin/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertext := make([]*ckks.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = ckks.NewCiphertext(tc.params, 1, lvl, tc.params.DefaultScale()*tc.params.DefaultScale())
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("out_z_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/CKKS_%d_csqr_relin/level_%d", ckks_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testCkksFpgaCtRotateCol(tc *testCkksContext, t *testing.T) {
	steps := []int{-500, 20, 200, 2000, 4000}
	glk := tc.kgen.GenRotationKeysForRotations(steps, false, tc.sk)

	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtRotateCol/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			steps := []int{-500, 20, 200, 2000, 4000}
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
			steps_str += ""
			project_path := fmt.Sprintf("%s/CKKS_%d_advanced_rotate_col/level_%d/steps_%s", ckks_fpga_base_path, tc.n_op, lvl, steps_str)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testCkksFpgaCtRotateRow(tc *testCkksContext, t *testing.T) {
	glk := tc.kgen.GenRotationKeysForRotations([]int{}, true, tc.sk)

	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtRotateRow/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertext := make([]*ckks.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = ckks.NewCiphertext(tc.params, 1, lvl, tc.params.DefaultScale())
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("arg_x", ciphertext1),
				acc.NewGoVectorArgument("arg_y", ciphertext),
			}

			project_path := fmt.Sprintf("%s/CKKS_%d_rotate_row/level_%d", ckks_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testCkksFpgaCtRescale(tc *testCkksContext, t *testing.T) {
	for _, lvl := range tc.testLevel {
		t.Run(testString("FpgaRunner/CtRescale/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectors(lvl, tc.params.DefaultScale()*float64(tc.params.Q()[lvl]), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertext := make([]*ckks.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = ckks.NewCiphertext(tc.params, 1, lvl-1, tc.params.DefaultScale())

			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("out_y_list", ciphertext),
			}
			project_path := fmt.Sprintf("%s/CKKS_%d_rescale/level_%d", ckks_fpga_base_path, tc.n_op, lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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

func testCkksFpgaCtDropLevel(tc *testCkksContext, t *testing.T) {
	drop_lvl := 2
	for _, lvl := range tc.testLevel {
		if lvl < drop_lvl {
			continue
		}

		t.Run(testString("FpgaRunner/CtDropLevel/op1=Ciphertext", tc.params, lvl), func(t *testing.T) {
			values1, _, ciphertext1 := newTestVectors(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk, complex(-1, -1), complex(1, 1))

			ciphertext := make([]*ckks.Ciphertext, tc.n_op)
			for i := range ciphertext {
				ciphertext[i] = ckks.NewCiphertext(tc.params, 1, lvl-drop_lvl, tc.params.DefaultScale())
			}

			args := []acc.GoVectorArgument{
				acc.NewGoVectorArgument("in_x_list", ciphertext1),
				acc.NewGoVectorArgument("out_y_list", ciphertext),
			}

			project_path := fmt.Sprintf("%s/CKKS_%d_drop_level/level_%d/drop_%d", ckks_fpga_base_path, tc.n_op, lvl, drop_lvl)
			project, err := acc.NewFheTaskFpga(project_path)
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
