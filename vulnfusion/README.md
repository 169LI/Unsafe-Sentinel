# VulnFusion - 高级漏洞挖掘工具

## 概述

VulnFusion 是一个融合 Rudra 的静态分析技术与 SafeDrop 的路径敏感数据流分析的 Rust 漏洞检测框架，面向内存安全、并发安全与 panic 安全问题，支持多格式报告输出与并行分析。当前版本已在大型工程上验证，支持深度扫描与多线程并行分析，并提供可用于 CI 的退出码语义。

## 架构

### 核心组件

1. Parser（`src/parser/`）
   - `rust_parser.rs`：Rust 源码解析
   - `ast_extractor.rs`：函数/结构体/特征等 AST 信息抽取
   - `mir_analyzer.rs`：MIR 中间表示分析

2. Graph（`src/graph/`）
   - `analysis_graph.rs`：通用分析图结构
   - `control_flow_graph.rs`：控制流分析与循环/支配关系
   - `data_flow_graph.rs`：数据流与 def-use/liveness
   - `call_graph.rs`：调用关系与环路检测

3. Detector（`src/detector/`）
   - `memory_safety_detector.rs`：内存安全（UAF、双重释放、越界等）
   - `concurrency_detector.rs`：并发问题（数据竞争、死锁等）
   - `panic_safety_detector.rs`：panic/unwind 安全
   - `pattern_detector.rs`：基于模式的快速检测

4. Analyzer（`src/analyzer/`）
   - `vulnerability_analyzer.rs`：分析调度与并行/顺序模式
   - `analysis_config.rs`：精度与性能配置
   - `analysis_results.rs`：结果结构与统计指标

5. Reporter（`src/reporter/`）
   - `report_generator.rs`：报告生成器
   - `formatters/`：JSON/HTML/Markdown/SARIF 等格式

6. Utils（`src/utils/`）
   - `file_utils.rs`：文件/工程发现与 IO
   - `logger.rs`：彩色日志与进度上报
   - `config.rs`：TOML 配置与命令行覆盖
   - `helpers.rs`：复杂度计算、字符串处理等工具
   - `error.rs`：统一错误类型与处理
   - `constants.rs`：常量与规则集合

## 主要能力

### 检测方向

1. 内存安全：UAF、双重释放、缓冲区越界、空指针等
2. 并发安全：数据竞争、死锁、竞态条件等
3. panic 安全：不安全的 `unwrap/expect/panic`、异常传播与不变式破坏
4. 模式检测：基于模式与特征的快速扫描，便于初筛
5. Send/Sync 变体违规、数组边界检查、API 误用、资源泄漏（见 `src/main.rs:229-236` 的类型列表）

### 分析模式

- Shallow：快速扫描
- Normal：均衡精度
- Deep：深度分析

### 输出格式

- JSON、HTML、Markdown（同时支持 Text/SARIF 报告生成）

### 退出码语义

- 当发现潜在漏洞时进程返回 `1`，便于在 CI 中作为失败条件；未发现漏洞返回 `0`（见 `src/main.rs:199-203`）。

### 命令与参数

- `analyze [PATH]`：分析目标工程或文件（默认当前目录）。
  - `-f, --format <json|html|markdown|text|sarif>` 输出格式
  - `-o, --output <FILE>` 输出文件路径（不指定则打印到终端）
  - `-j, --threads <N>` 线程数，`0` 表示自动
  - `-p, --parallel` 启用并行分析
  - `--depth <shallow|normal|deep>` 分析深度
  - `-t, --vuln-types <...>` 按类型过滤（如 `memory-safety, concurrency`）
  - `--exclude <PATH>` 排除路径（可多次传入）
  - `--config <FILE>` 指定配置文件
- `benchmark`：性能基准（当前为占位实现）
- `generate`：生成示例漏洞工程（当前为占位实现）
- `info [--all|<type>]`：展示支持的漏洞类型（见 `src/main.rs:229-236`）

## 使用示例

基础分析：
```
vulnfusion analyze /path/to/rust/project --format json --output report.json
```

深度分析并输出 HTML：
```
vulnfusion analyze /path/to/project --depth deep --parallel -j 0 --format html --output report.html
```

基准测试：
```
vulnfusion benchmark /path/to/test/cases
```

生成样例漏洞工程：
```
vulnfusion generate --count 10 --output vulnerable_sample --vuln-types memory-safety,panic-safety
```

内置漏洞示例可参考：`examples/vulnerable_examples.rs`

## 与现有工具融合

### Rudra
- 继承其 panic 安全与不变式相关技术
- 与路径敏感的数据流结合减少误报

### SafeDrop
- 借鉴 Tarjan 等适配规模分析的方法
- 在跨 crate 与生命周期分析上增强

## 性能特性

- 并行分析（rayon）
- 增量分析与缓存
- 内存/超时可配置
- 实时进度上报与性能指标

## 配置方式

- 命令行参数、TOML 文件、环境变量与运行时覆盖

## 后续规划

1. 机器学习：模式识别与误报抑制
2. 跨语言：C/C++/FFI 边界安全
3. 可视化：交互式图与历史趋势
4. 云端：分布式分析与协作

## 技术栈

- Rust、serde、petgraph、rayon、clap 等

VulnFusion 旨在为竞赛与工业场景提供高效、可扩展的 Rust 漏洞检测能力。