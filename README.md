# VulnFusion 使用说明（中文）

## 工具概览

VulnFusion 是一个面向竞赛与工程实践的 Rust 静态漏洞检测工具，支持“严格模式”和“竞赛模式（仅确证漏洞）”。当前实现以启发式图分析为主，结合后处理去重与抑制，聚焦以下类型：

- 内存安全：越界写/读、未初始化读、无效转换、空指针解引用、使用后释放、双重释放、内存泄漏
- 并发安全：数据竞争、同步不当、原子性违背、死锁、竞态条件
- API 误用：`Vec::from_raw_parts` 等不安全 API 的不当使用
- Panic 安全：`impl Drop::drop` 中的 `panic!/unwrap/expect/assert!`

## 运行方式

基础命令：

```
cargo run --bin vulnfusion -- analyze <目标路径> --format markdown --output <报告路径>
```

常用参数：

- `--threads <N>`：线程数（0 自动）
- `--parallel`：并行分析
- `--depth <shallow|normal|deep>`：分析深度
- `--exclude <glob>`：排除路径（可多次）
- `--min-confidence <0.0-1.0>`：最小置信度阈值
- `--min-severity <info|low|medium|high|critical>`：最小严重度
- `--verified-only`：竞赛模式，仅保留确证漏洞
- `--max-verified <N>`：竞赛模式下条目上限（不限制可设一个很大的数）

竞赛模式示例（仅确证，数量不限，排除测试/示例/文档）：

```
cargo run --bin vulnfusion -- analyze d:\漏洞挖掘\detector\project\rust-main \
  --format markdown --output d:\漏洞挖掘\detector\reports\rust-main-verified-unlimited.md \
  --threads 0 --parallel --depth shallow \
  --min-confidence 0.9 --min-severity high \
  --verified-only --max-verified 999999 \
  --exclude **/tests/** --exclude **/benches/** --exclude **/examples/** --exclude **/doc/**
```

## 确证规则（verified-only）

为避免“风险点”刷数，竞赛模式只保留具有强证据的条目：

- 越界：`get_unchecked(const)` 或指针算术 `ptr.add/offset` 明显越界
- 双重释放：`free/dealloc` 在同片段出现多次
- 使用后释放：包含 `free/dealloc/drop` 后继续指针解引用 `*`
- 未初始化读：`MaybeUninit` 与 `assume_init` 的组合使用
- 空指针解引用：`ptr::null/_mut` 与解引用 `*`，且无空指针检查
- 并发数据竞争：`static mut/UnsafeCell` 与线程使用，且无 `Mutex/RwLock/Atomic`
- 同步不当：`unsafe impl Send/Sync` 且出现原始指针或 `RefCell/Cell/NonNull`
- Panic 安全：必须在 `impl Drop::drop` 内出现 `panic!/unwrap/expect/assert!`

并进行路径级排除：`/tests/`、`/benches/`、`/examples/`、`/doc/` 以及常见测试/基准文件名。

## 结果去重与抑制

- 同类型/同文件/近似行号聚合为一条
- 出现边界检查或同步原语（如 `len()/assert!/Mutex/RwLock/Atomic`）即抑制

## 目录结构建议

- `vulnfusion/`：工具源码（CLI、分析器、检测器、报告器、utils）
- `project/`：被扫描的目标工程（不修改其代码）
- `reports/`：扫描输出（建议仅保留 `*-verified-unlimited.md`）

为保持清晰，已删除旧版 `strict/verified` 报告与中间 JSON；仅保留竞赛模式报告。

## 常见问题

- 为什么 `rust-main` 条目较多？体量与职责决定触发面广；竞赛模式已剔除测试/示例路径，仅保留强证据条目。
- 是否为 Rudra 与 RAPX 的结合？VulnFusion 借鉴了它们的思想与模式，但并非简单拼接，当前实现以启发式与后处理为主，逐步增强图分析能力。

## 许可证与贡献

工具仅用于竞赛与研究目的；欢迎在不修改目标工程的前提下提 PR 优化规则与抑制策略。