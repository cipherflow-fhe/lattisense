# Lattigo fork 功能迁移 Checklist

本文用于记录旧 fork `/home/liyb/github-projects/lattigo` 中 `c53bba8ccf6edef6cb9e02e9aecb4a7741a492d7..3938867` 的功能修改，并作为迁移到当前 submodule `/home/liyb/github-projects/lattisense/fhe_ops_lib/lattigo` 的 checklist。

## 迁移原则

- 目标不是描述当前 submodule 的完整状态，而是记录旧 fork 中需要迁移的功能点。
- 当前 submodule 已经换到 upstream 最新 Lattigo v6 结构，不能直接拷贝旧 fork v3 路径。
- `go_sdk/` 相关内容最后迁移；先把 Go 层 API、序列化、编码、key、bootstrapping 能力补齐。
- 当前 submodule 中已有的本地修改不要覆盖，应在其基础上继续补齐。

## 当前 submodule 状态

| 项目 | 当前状态 |
| ---- | -------- |
| 路径 | `/home/liyb/github-projects/lattisense/fhe_ops_lib/lattigo` |
| 分支 | `port/upstream-main-20260721` |
| 基准 | `upstream/main`，当前分支 ahead 1 个 module-path 修改提交 |
| 当前提交 | `1d97c15 chore: update module path to cipherflow-fhe` |
| module | `github.com/cipherflow-fhe/lattigo` |
| Go 版本 | `go 1.25.0` |
| `go_sdk/` | 当前 submodule 中不存在 |

### 当前已有本地修改，迁移时不要覆盖

这些文件已经有未提交的 CipherFlow 修改，应作为“已部分迁移”的基础：

- `circuits/ckks/bootstrapping/keys.go`
  - sparse bootstrapping key 使用完整 `params.P()`，不是只取 `P[:1]`。
- `core/rlwe/metadata.go`
  - `PlaintextMetaData` 增加 `IsRingT`，并支持 metadata marshal/unmarshal。
- `core/rlwe/params.go`
  - `ParametersLiteral` / `Parameters` 增加 `IsFpga` / `isFpga`，并提供 `IsFpga()`。
- `schemes/ckks/ckks.go`
  - 增加 `NewPlaintextRingT(params)`。
- `schemes/ckks/encoder.go`
  - 增加 `encodeCoeffsRingT()`、`RingTToPt()`，并在 `Encode()` 中识别 `pt.IsRingT`。
  - 已补 `EncodeCoeffsRingT` 的 FPGA 分支和 `EmbedRingT` 的 `ecd.prec <= 53` 路径。
  - `RingTToPt` 已增加输出 `pt` 的约束检查：必须是非 RingT，并且 `IsNTT=true`。
  - 剩余重点是对齐验证 sparse packing / FPGA RingT layout 是否完全匹配旧 fork。
- `schemes/ckks/params.go`
  - `ckks.ParametersLiteral` 增加并传递 `IsFpga`。

## 旧 v3 fork 到新 v6 submodule 路径映射

| 旧 fork 路径/类型 | 新 submodule 路径/类型 |
| ----------------- | ----------------------- |
| `rlwe/` | `core/rlwe/` |
| `ckks/` | `schemes/ckks/` |
| `bfv/` | `schemes/bgv/`，BFV 语义通过 BGV 参数适配 |
| `ckks/bootstrapping/` | `circuits/ckks/bootstrapping/` |
| `ckks/advanced/` | `circuits/ckks/` 下相关 circuit |
| `dbfv/`, `dckks/`, `drlwe/` | `multiparty/` |
| `rlwe.RotationKeySet` | v6 中主要对应 `rlwe.GaloisKey` |
| `bfv.PlaintextRingT` | v6 中倾向用 `*rlwe.Plaintext` + `IsRingT=true` 表示 |
| `bfv.PlaintextMul` / `ckks.PlaintextMul` | v6 中需用 metadata/编码状态适配，避免机械搬类型 |
| `go_sdk/` | 当前不存在，最后重新移植 |

## 迁移 Checklist

### Phase 0：保护当前 submodule 修改并建立基线

- [ ] 确认当前 6 个未提交修改文件是否需要先单独提交或保存 patch。
- [ ] 在迁移前运行一次当前 submodule 的最小构建/测试，记录现有失败点。
- [ ] 优先确认 `schemes/ckks/encoder.go` 中 `EmbedRingT` 缺失导致的编译状态。
- [ ] 后续每个阶段完成后单独运行相关 package 测试，避免和 `go_sdk` 大迁移混在一起。

### Phase 1：补齐当前已经开始迁移的 CKKS RingT / FPGA 编码能力

目标：让当前已有的 `IsRingT` / `IsFpga` / `NewPlaintextRingT` / `RingTToPt` 修改闭环可用。

- [x] 在 `encodeCoeffsRingT()` 的 `case []float64` 中加入 `params.IsFpga()` 处理。
  - 旧 fork 来源：`ckks/encoder.go` 的 `EncodeCoeffsRingT`。
  - FPGA 路径使用 `scale / 2^(32-26)`，并按 Q/P 最大 bit length 选择 31/63 符号位表示。
  - 非 FPGA 路径保留原 CRT fixed-point 编码。
- [x] 在 `encodeCoeffsRingT()` 的 `case []*big.Float` 中禁止 FPGA 路径。
  - `params.IsFpga()==true` 时直接返回错误。
  - 原因：当前先只迁移 double-precision FPGA RingT 路径，不支持 arbitrary precision FPGA RingT 编码。
- [x] 实现 `schemes/ckks/encoder.go` 中缺失的 `Encoder.EmbedRingT(...)` 的 `ecd.prec <= 53` 路径。
  - 旧 fork 来源：`ckks/encoder.go` 的 `EmbedRingT`。
  - 新代码适配 v6 当前调用方式：`ecd.EmbedRingT(values, pt.MetaData, pt.Value)`。
  - 只支持 `[]complex128` / `[]float64`，`ecd.prec > 53` 直接报错。
  - 需要继续确认 sparse packing 与 FPGA RingT 数据布局是否完全匹配旧 fork。
- [x] 移植 CKKS RingT fixed-point helper 的 double-precision 部分。
  - 旧 fork 来源：`ckks/utils.go`。
  - 目标：`schemes/ckks/utils.go`。
  - 已加入 `Complex128ToFixedPointRingT`、`singleFloat64ToFixedPointFpga`。
- [x] 修正 `RingTToPt` 的基础约束。
  - 输入 `ptRingT` 默认/要求是非 NTT、非 Montgomery 的 RingT plaintext。
  - 目标输出 `pt` 必须先检查 `pt.IsRingT == false`，避免把 RingT plaintext 当作普通 plaintext 输出。
  - 目标输出 `pt` 必须先检查 `pt.IsNTT == true`。
  - FPGA 路径按 31/63 符号位和 mask 还原，再写入目标 level。
  - 非 FPGA 路径保留从 Q0 到目标 level 的 basis extension。
  - 转换完成后再根据目标 `pt` 的 `IsBatched` / `IsNTT` / `IsMontgomery` metadata 做后处理。
- [ ] 对齐验证 sparse packing / FPGA RingT layout。
  - 旧 fork 相关提交：`ded78f5 fix: use LogSlots for sparse packing in encode/decode and RingTToMul`。
  - 需要确认当前 `EmbedRingT` 使用 metadata 中的 `LogDimensions.Cols` 后，生成的 RingT polynomial layout 与旧 fork 在 sparse packing 下完全一致。
  - 需要确认 `IsFpga=true` 时，`EncodeCoeffsRingT`、`EmbedRingT`、`RingTToPt` 的符号位、mask、`2^(32-26)` scale 修正与旧 fork 行为一致。
- [x] 明确不迁移 `EncodeRingT(values, ptRingT, logSlots)` wrapper。
  - 当前不需要显式 wrapper，使用 `Encode(values, pt)` + `pt.IsRingT=true`。
- [x] 明确不迁移 `RingTToMul`。
  - 当前不需要该 API。
- [x] 明确不新增专门的 RingT 测试。
  - 当前仅保留现有 package 测试和必要的手动/对齐验证。

### Phase 2：迁移 ring / RLWE 底层工具和紧凑序列化

目标：先补齐非 CGO 的底层能力，为 key/ciphertext 压缩、GPU ABI 序列化和后续 `go_sdk` 做基础。

- [ ] 迁移 `ring.NewRingWithoutNTT(N, Moduli)`。
  - 旧 fork 来源：`ring/ring.go`。
  - 目标：`ring/ring.go`。
  - 用于不支持 NTT 的 plaintext modulus/ring 场景。
- [ ] 迁移 `(*Ring).InvMFormAndMulByPow2(...)`。
  - 旧 fork 来源：`ring/ring_operations.go`。
  - 目标：v6 的 `ring/operations.go`。
  - 需要维护 `IsMForm` 状态语义。
- [ ] 迁移 pow-of-2 plaintext modulus 相关 basis extension。
  - 旧 fork 来源：`ring/ring_basis_extension.go`。
  - 目标：v6 的 `ring/basis_extension.go`。
  - 包括 `ModUpExactPowOf2` 和对应 `multSumPowOf2` fast path。
- [ ] 新增 `core/rlwe/bit_stream.go`。
  - 旧 fork 来源：`rlwe/bit_stream.go`。
  - 迁移 bit-packed polynomial/key/ciphertext 序列化基础函数。
  - 注意 v6 key/poly 结构变化，不要逐行硬拷旧 `ringqp` 代码。
- [ ] 迁移 32-bit marshal/unmarshal helpers。
  - 旧 fork 来源：`rlwe/marshaler.go`、`rlwe/ringqp/ringqp.go`。
  - 目标：`core/rlwe/` 下新文件，例如 `marshal32.go`。
  - 覆盖 `SecretKey`、`PublicKey`、`RelinearizationKey`、Galois/rotation key 的 32-bit 紧凑格式。
- [ ] 迁移压缩 ciphertext / key seed 展开逻辑。
  - 旧 fork 来源：`rlwe/elements.go`、`rlwe/encryptor.go`、`rlwe/keys.go`。
  - 目标：`core/rlwe/`。
  - v6 已有 `EvaluationKey` / seed 相关机制，需先对齐现有 upstream API，再决定是 adapter 还是新增兼容 API。

### Phase 3：迁移 RLWE keygen 扩展

目标：恢复旧 fork 中用于固定 seed、指定 level keygen、GPU/FPGA 上下文序列化的 key 生成能力。

- [ ] 迁移 `GenSecretKeyWithSeed(seed []byte)`。
  - 旧 fork 来源：`rlwe/keygenerator.go`。
  - 目标：`core/rlwe/keygenerator.go`。
- [ ] 迁移/适配指定 level 的 relinearization key 生成。
  - 旧 fork 来源：`GenRelinearizationKeyLvl(...)`。
  - v6 目标：优先用 `EvaluationKeyParameters{LevelQ: level}` 实现 wrapper。
- [ ] 迁移/适配指定 level 的 rotation/galois key 生成。
  - 旧 fork 来源：`GenRotationKeysLvl(...)`、`NewRotationKeySetLvl(...)`。
  - v6 目标：映射到 `GaloisKey` / `EvaluationKeyParameters`。
- [ ] 迁移 key decompression adapter。
  - 旧 fork 来源：`CiphertextQP.Decompress`、`SwitchingKey.Decompress`。
  - v6 目标：尽量复用 upstream 的 `Expand`/seed 机制。

### Phase 4：迁移 CKKS evaluator 与 bootstrapping 非 CGO 能力

目标：恢复旧 fork 中 CKKS 算子扩展和 bootstrapping 初始化性能优化。

- [ ] 迁移 CKKS `MultByi` / `DivByi`。
  - 旧 fork 来源：`ckks/evaluator.go`。
  - 目标：`schemes/ckks/evaluator.go`。
  - 包括 `MultByi`、`MultByiNew`、`DivByi`、`DivByiNew`。
  - 需要基于 v6 evaluator 的 automorphism/conjugation/negation 实现方式重写。
- [ ] 迁移 `utils.WorkerPool(numWorkers, jobs)`。
  - 旧 fork 来源：`utils/worker_pool.go`。
  - 目标：`utils/worker_pool.go`。
- [ ] 迁移 bootstrapping split-constructor。
  - 旧 fork 来源：`ckks/bootstrapping/bootstrapper.go`。
  - 目标：`circuits/ckks/bootstrapping/`。
  - 需要新增类似 `BootstrapperBase`、`NewBootstrapperBase`、`NewBootstrapperFromBase` 的结构。
  - 目标是把参数相关预计算和 evaluation key 生成拆开，使二者可并行。
- [ ] 保留当前已迁移的 sparse bootstrapping P-basis 修改。
  - 当前文件：`circuits/ckks/bootstrapping/keys.go`。
  - 不要回退 `P: params.P()`。

### Phase 5：迁移 BGV/BFV 相关功能

目标：旧 fork 的 `bfv/` 在 v6 中需要迁移到 `schemes/bgv/`，重点是 RingT、coeff encoding、压缩序列化和 helper API。

- [ ] 迁移 BFV RingT coeff encode/decode API。
  - 旧 fork 来源：`bfv/encoder.go`。
  - 目标：`schemes/bgv/encoder.go`。
  - 包括 `EncodeCoeffs`、`EncodeCoeffsRingT`、`DecodeCoeffsUint`、`DecodeCoeffsUintNew`。
  - 先检查 v6 BGV 已有 `EncodeRingT` 是否可复用，避免重复实现。
- [ ] 迁移 BFV/BGV compressed ciphertext wrapper。
  - 旧 fork 来源：`bfv/ciphertext.go`。
  - 目标：`schemes/bgv/` 下新增文件。
  - 依赖 Phase 2 的 bit-stream 序列化。
- [ ] 迁移 BFV/BGV ciphertext `ToBytes` / `FromBytes`。
  - 旧 fork 来源：`bfv/ciphertext.go`。
  - 目标：`schemes/bgv/`。
  - 需要支持 `n_drop_bit_0` / `n_drop_bit_1` 这类 ABI 压缩参数。
- [ ] 迁移 BFV RingT plaintext serialization helper 的 Go 层基础。
  - 旧 fork 对外 API 在 `go_sdk/main.go`，但底层依赖应先在 `schemes/bgv` 中稳定。
- [ ] 验证 BFV/BGV pow-of-2 plaintext modulus 路径。
  - 依赖 Phase 2 的 `ModUpExactPowOf2` 和 `InvMFormAndMulByPow2`。

### Phase 6：跨模块验证与迁移前收敛

目标：在开始 `go_sdk/` 前，确保 Go 层能力可独立测试。

- [ ] CKKS RingT encode/decode 基础测试通过。
- [ ] CKKS RingT -> regular plaintext 转换测试通过。
- [ ] CKKS `MultByi` / `DivByi` 与原旧 fork 行为对齐。
- [ ] BGV/BFV RingT coeff encode/decode 测试通过。
- [ ] RLWE key 32-bit/bit-packed 序列化 round-trip 测试通过。
- [ ] compressed ciphertext/key seed 展开测试通过。
- [ ] bootstrapping split-constructor 与普通 constructor 结果等价。
- [ ] 确认 `go test ./...` 的失败项只来自尚未迁移的 `go_sdk` 或已知 upstream 差异。

### Phase 7：最后迁移 `go_sdk/` / CGO ABI

目标：在 Go 层 API 稳定后，再恢复外部 C ABI。该阶段工作量最大，且高度依赖前面所有阶段。

- [ ] 创建 `go_sdk/` 目录骨架。
  - 旧 fork 来源：`go_sdk/`。
  - 包括 `build.sh`、`strip_cgo_line.cmake`、header 生成流程。
- [ ] 迁移 `go_sdk/conversion.go`。
  - 更新 v3 到 v6 package 路径：
    - `rlwe` -> `core/rlwe`
    - `ckks` -> `schemes/ckks`
    - `bfv` -> `schemes/bgv`
    - multiparty 包路径按 v6 结构重写
  - 保留 flat poly helper、NTT/InvNTT/MulByPow2 inplace API。
  - 保留 Windows CGO 兼容修复和 `stdint.h` include 修复。
- [ ] 迁移 `go_sdk/c_struct_import_export.go`。
  - 保留 flat ABI struct 导入导出。
  - 保留 `Export*Key(..., mf_nbits)` 中合并 MForm 转换的逻辑。
  - 保留 in-place ciphertext import 语义。
  - `RotationKeySet` 相关 API 需要改成 v6 `GaloisKey` 语义。
- [ ] 迁移 `go_sdk/main.go`。
  - BFV/BGV context、CKKS context、key handle、plaintext/ciphertext handle。
  - encrypt/decrypt/evaluator wrapper。
  - `MultByi` / `DivByi` C export。
  - BFV RingT plaintext serialize/deserialize export。
  - sparse RingT encode overloads。
- [ ] 迁移 `go_sdk/bootstrap.go`。
  - CKKS bootstrapping context 创建、key 注入、bootstrap 调用。
  - context advanced serialization / deserialization。
  - lazy-init EVK nil guard。
  - 使用 Phase 4 的 split-constructor 暴露并行初始化路径。
- [ ] 迁移 `go_sdk/multiparty.go`。
  - 旧 `dbfv` / `dckks` / `drlwe` API 要映射到 v6 `multiparty`。
  - 需要重新确认 C ABI 函数签名是否维持旧 FHE SDK 兼容。
- [ ] 重新生成 `go_sdk/liblattigo.h`。
  - 不手写最终头文件。
  - 通过 cgo 生成后再执行 sanitize/post-process。
- [ ] 迁移 `go_sdk/liblattigo_to_fhe_lib.py`。
  - 根据新生成的 `liblattigo.h` 更新 wrapper 生成逻辑。
- [ ] 验证外部 C ABI 编译。
  - 至少覆盖 BFV/BGV、CKKS、bootstrapping、key import/export、serialization 这几类函数。

## 旧 fork 功能摘要

旧 fork 从 `c53bba8` 到 `3938867` 的整体修改目标，是把 Lattigo 改造成 CipherFlow/FHE SDK 可调用的底层库：

1. 模块路径切换到 `github.com/cipherflow-fhe/lattigo`。
2. 新增 `go_sdk/`，提供 CGO/C ABI 封装。
3. 增加 BFV/CKKS 的 RingT、PlaintextMul、系数编码、复杂数编码等接口。
4. 增加紧凑序列化、压缩密文、压缩公钥、压缩 switching key 支持。
5. 增强 GPU/FPGA ABI 适配：flat layout、MForm 转换、pow-of-2 T 支持。
6. 加速 keygen/bootstrap 初始化，增加并行 worker pool。
7. 修复 bootstrapping/context 序列化、sparse packing、CGO 头文件兼容等问题。

## 旧 fork 主要提交脉络

- `c8aa9cf`：最大的一次集成，完成模块路径切换、`go_sdk` 初版、BFV/CKKS/RLWE 扩展。
- `df69e63`：并行 keygen / bootstrapper base 初始化。
- `3c6d09f`：把 MForm 转换合并进 key/plaintext export，移除单独转换 API。
- `062888a` / `0fec073`：flat ABI struct/export helper 重构。
- `ded78f5`：修复 sparse packing 使用 `LogSlots`。
- `8bbd292`：恢复 FPGA `EncodeCoeffsRingT` 路径。
- `b084341`：新增 BFV RingT plaintext serialization helper。
- `32c407f`：暴露 CKKS 乘/除虚数单位操作。
- `dfcfd75` / `0ffaee0` / `6731e3a`：修复 context / BTP serialization。
- `505cd8a` / `8186fff` / `c009621`：CGO Windows / stdint header 兼容修复。
