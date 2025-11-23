// 中文说明：
// 这是 VulnFusion 的命令行入口，基于 clap 定义四个子命令：
// 1) analyze：对目标工程进行漏洞分析并输出报告；
// 2) benchmark：性能基准；
// 3) generate：生成带缺陷的示例工程；
// 4) info：查看支持的漏洞类型。支持 verbose/quiet 以及自定义配置文件。
use clap::{Parser, Subcommand};
use vulnfusion::utils::error::Result;
use vulnfusion::utils::config as ext_cfg;
use std::path::PathBuf;
use tracing::{info, warn, error};
use colored::*;

use vulnfusion::analyzer::VulnerabilityAnalyzer;
use vulnfusion::reporter::ReportGenerator;

#[derive(Parser)]
#[command(name = "vulnfusion")]
#[command(about = "融合 Rudra 与 SafeDrop 技术的高级漏洞检测工具")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    #[arg(short, long, global = true)]
    verbose: bool,
    
    #[arg(short, long, global = true)]
    quiet: bool,
    
    #[arg(long, global = true)]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// 分析 Rust 工程中的潜在漏洞
        Analyze {
        /// 输入工程或单文件路径
        #[arg(default_value = ".")]
        path: PathBuf,
        
        /// 输出格式（仅 markdown）
        #[arg(short, long, default_value = "json")]
        format: String,
        
        /// 输出文件路径（不指定则打印到终端）
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// 使用的线程数（0 表示自动）
        #[arg(short = 'j', long, default_value = "0")]
        threads: usize,
        
        /// 是否启用并行分析
        #[arg(short, long)]
        parallel: bool,
        
        /// 分析深度（shallow, normal, deep）
        #[arg(long, default_value = "normal")]
        depth: String,
        
        /// 按漏洞类型过滤（如 memory-safety, concurrency）
        #[arg(short = 't', long)]
        vuln_types: Vec<String>,
        
        /// 排除路径（支持多次传入）
        #[arg(long)]
        exclude: Vec<String>,
        #[arg(long)]
        min_confidence: Option<f64>,
        #[arg(long)]
        min_severity: Option<String>,
        #[arg(long)]
        verified_only: bool,
        #[arg(long, default_value_t = 3)]
        max_verified: usize,
        },
    
    /// 运行性能基准测试
    Benchmark {
        /// 测试数据集路径
        #[arg(default_value = "benchmarks")]
        dataset: PathBuf,
        
        /// 迭代次数
        #[arg(short, long, default_value = "5")]
        iterations: usize,
        
        /// 是否进行内存画像
        #[arg(long)]
        profile_memory: bool,
    },
    
    /// 生成含漏洞的示例工程
    Generate {
        /// 输出目录
        #[arg(default_value = "vulnerable_sample")]
        output: PathBuf,
        
        /// 生成漏洞数量
        #[arg(short, long, default_value = "10")]
        count: usize,
        
        /// 包含的漏洞类型
        #[arg(short = 't', long)]
        vuln_types: Vec<String>,
    },
    
    /// 展示支持的漏洞类型信息
    Info {
        /// 指定漏洞类型（不填显示全部）
        vuln_type: Option<String>,
        
        /// 是否展示全部类型
        #[arg(short, long)]
        all: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    let log_level = if cli.quiet {
        "error"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };
    
    tracing_subscriber::fmt()
        .with_env_filter(format!("vulnfusion={}", log_level))
        .init();
    
    info!("{}", "VulnFusion - 高级漏洞检测工具".bright_green().bold());
    info!("{}", "融合 Rudra 与 SafeDrop 技术以提升检测效果".bright_blue());
    
    match cli.command {
        Commands::Analyze { path, format, output, threads, parallel, depth, vuln_types, exclude, min_confidence, min_severity, verified_only, max_verified } => {
            analyze_command(path, format, output, threads, parallel, depth, vuln_types, exclude, cli.config, min_confidence, min_severity, verified_only, max_verified).await
        }
        Commands::Benchmark { dataset, iterations, profile_memory } => {
            benchmark_command(dataset, iterations, profile_memory).await
        }
        Commands::Generate { output, count, vuln_types } => {
            generate_command(output, count, vuln_types).await
        }
        Commands::Info { vuln_type, all } => {
            info_command(vuln_type, all)
        }
    }
}

async fn analyze_command(
    path: PathBuf,
    format: String,
    output: Option<PathBuf>,
    threads: usize,
    parallel: bool,
    depth: String,
    vuln_types: Vec<String>,
    exclude: Vec<String>,
    config_path: Option<PathBuf>,
    min_confidence: Option<f64>,
    min_severity: Option<String>,
    verified_only: bool,
    max_verified: usize,
) -> Result<()> {
    info!("Starting vulnerability analysis...");
    
    // Validate input path
    if !path.exists() {
        error!("Path does not exist: {}", path.display());
        return Err(Box::<dyn std::error::Error + Send + Sync>::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Invalid input path",
        )));
    }
    
    // Configure analysis parameters
    let mut analyzer = VulnerabilityAnalyzer::new();
    
    if let Some(cfg_path) = config_path.clone() {
        match ext_cfg::AnalysisConfig::from_file(&cfg_path) {
            Ok(c) => {
                analyzer.set_parallel(c.enable_parallel);
                analyzer.set_thread_count(c.performance_settings.max_threads);
                analyzer.set_excluded_paths(c.exclude_patterns.clone());
                let precision_str = c.precision.as_str();
                analyzer.set_depth(precision_str);
                if !c.vulnerability_filters.categories.is_empty() {
                    analyzer.set_vulnerability_filters(c.vulnerability_filters.categories.clone());
                }
                analyzer.set_min_confidence(c.vulnerability_filters.confidence_threshold);
                let sev = c.vulnerability_filters.min_severity.numeric_value() as i32;
                analyzer.set_min_severity_level(sev);
            }
            Err(e) => {
                warn!("Failed to load config file: {}", e);
            }
        }
    }
    
    // Override with CLI options
    analyzer.set_parallel(parallel);
    analyzer.set_depth(&depth);
    analyzer.set_thread_count(threads);
    if !exclude.is_empty() {
        analyzer.set_excluded_paths(exclude);
    }
    if !vuln_types.is_empty() {
        analyzer.set_vulnerability_filters(vuln_types);
    }
    if let Some(mc) = min_confidence { analyzer.set_min_confidence(mc); }
    if let Some(ms) = min_severity { analyzer.set_min_severity_str(&ms); }
    
    // Run analysis
    info!("Analyzing project: {}", path.display());
    let mut results = analyzer.analyze(&path).await?;
    let pp = vulnfusion::analyzer::PostProcessor::with_verified(verified_only, Some(max_verified));
    results = pp.process(results);
    
    // Generate report
    let mut reporter = ReportGenerator::new();
    reporter.set_format(&format);
    
    if let Some(output_path) = output {
        reporter.save_to_file(&results, &output_path)?;
        info!("Report saved to: {}", output_path.display());
    } else {
        let report = reporter.generate_report(&results)?;
        println!("{}", report);
    }
    
    // Print summary
    let total_vulns = results.vulnerabilities.len();
    if total_vulns > 0 {
        warn!("Found {} potential vulnerabilities", total_vulns);
        std::process::exit(1);
    } else {
        info!("No vulnerabilities detected - code looks secure!");
    }
    
    Ok(())
}

async fn benchmark_command(dataset: PathBuf, iterations: usize, profile_memory: bool) -> Result<()> {
    info!("Running performance benchmarks...");
    
    // TODO: Implement benchmark functionality
    info!("Benchmark functionality will be implemented in the next phase");
    
    Ok(())
}

async fn generate_command(output: PathBuf, count: usize, vuln_types: Vec<String>) -> Result<()> {
    info!("Generating vulnerable sample code...");
    
    // TODO: Implement sample generation functionality
    info!("Sample generation functionality will be implemented in the next phase");
    
    Ok(())
}

fn info_command(vuln_type: Option<String>, all: bool) -> Result<()> {
    if all || vuln_type.is_none() {
        println!("{}", "支持的漏洞类型:".bright_yellow().bold());
        println!("  • {}", "memory-safety - Memory safety violations (UAF, double-free, etc.)");
        println!("  • {}", "concurrency - Concurrency issues (data races, deadlocks, etc.)");
        println!("  • {}", "panic-safety - Panic safety violations");
        println!("  • {}", "send-sync - Send/Sync variance violations");
        println!("  • {}", "bounds-check - Array bounds violations");
        println!("  • {}", "api-misuse - API misuse patterns");
        println!("  • {}", "resource-leak - Resource leak detection");
    }
    
    if let Some(vt) = vuln_type {
        println!("\n{}", format!("{} 详情:", vt).bright_cyan());
        // TODO: Add detailed descriptions for each vulnerability type
    }
    
    Ok(())
}
