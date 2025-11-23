// 中文说明：
// RustParser 负责将 Rust 源文件解析为语法树（AST），并抽取函数、结构体、
// trait、枚举等信息；可选地识别 unsafe 代码块并记录上下文，供后续漏洞
// 检测与图分析使用。
use crate::utils::error::Result;
use std::path::Path;
use std::fs;
use tracing::{debug, info};
use syn::{File, Item, ItemFn, ItemStruct, ItemImpl, ItemTrait, ItemEnum};
use quote::ToTokens;

#[derive(Debug, Clone)]
pub struct RustAst {
    pub file_path: String,
    pub syntax_tree: File,
    pub functions: Vec<ItemFn>,
    pub structs: Vec<ItemStruct>,
    pub implementations: Vec<ItemImpl>,
    pub traits: Vec<ItemTrait>,
    pub enums: Vec<ItemEnum>,
    pub unsafe_blocks: Vec<UnsafeBlockInfo>,
    pub lines_of_code: usize,
}

#[derive(Debug, Clone)]
pub struct UnsafeBlockInfo {
    pub line_start: usize,
    pub line_end: usize,
    pub content: String,
    pub context: String,
}

pub struct RustParser {
    enable_unsafe_detection: bool,
    enable_macro_expansion: bool,
}

impl RustParser {
    pub fn new() -> Self {
        Self {
            enable_unsafe_detection: true,
            enable_macro_expansion: false,
        }
    }
    
    pub fn with_unsafe_detection(mut self, enabled: bool) -> Self {
        self.enable_unsafe_detection = enabled;
        self
    }
    
    pub fn with_macro_expansion(mut self, enabled: bool) -> Self {
        self.enable_macro_expansion = enabled;
        self
    }
    
    pub fn parse_file(&self, file_path: &Path) -> Result<RustAst> {
        // 解析单个 Rust 文件为 AST，并统计基础信息与 unsafe 块位置
        debug!("Parsing Rust file: {}", file_path.display());
        
        let content = fs::read_to_string(file_path)?;
        let syntax_tree = syn::parse_file(&content)?;
        
        let mut ast = RustAst {
            file_path: file_path.to_string_lossy().to_string(),
            syntax_tree: syntax_tree.clone(),
            functions: Vec::new(),
            structs: Vec::new(),
            implementations: Vec::new(),
            traits: Vec::new(),
            enums: Vec::new(),
            unsafe_blocks: Vec::new(),
            lines_of_code: content.lines().count(),
        };
        
        // Extract different code elements
        self.extract_items(&syntax_tree, &mut ast)?;
        
        // Detect unsafe blocks if enabled
        if self.enable_unsafe_detection {
            self.detect_unsafe_blocks(&content, &mut ast)?;
        }
        
        info!("Parsed {} functions, {} structs, {} impl blocks, {} traits, {} enums",
              ast.functions.len(), ast.structs.len(), ast.implementations.len(),
              ast.traits.len(), ast.enums.len());
        
        if !ast.unsafe_blocks.is_empty() {
            info!("Found {} unsafe blocks", ast.unsafe_blocks.len());
        }
        
        Ok(ast)
    }
    
    fn extract_items(&self, file: &File, ast: &mut RustAst) -> Result<()> {
        // 遍历语法树，抽取常见顶层元素，供后续检测使用
        for item in &file.items {
            match item {
                Item::Fn(func) => {
                    ast.functions.push(func.clone());
                }
                Item::Struct(strct) => {
                    ast.structs.push(strct.clone());
                }
                Item::Impl(impl_block) => {
                    ast.implementations.push(impl_block.clone());
                }
                Item::Trait(trait_item) => {
                    ast.traits.push(trait_item.clone());
                }
                Item::Enum(enum_item) => {
                    ast.enums.push(enum_item.clone());
                }
                _ => {
                    // Handle other item types as needed
                }
            }
        }
        
        Ok(())
    }
    
    fn find_unsafe_blocks(&self, content: &str) -> Result<Vec<UnsafeBlockInfo>> {
        // 线性扫描并计数花括号，定位 unsafe 代码块的起止行与上下文
        let lines: Vec<&str> = content.lines().collect();
        let mut unsafe_blocks = Vec::new();
        let mut in_unsafe_block = false;
        let mut unsafe_start = 0;
        let mut brace_count: usize = 0;
        
        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            
            if trimmed.starts_with("unsafe") && !in_unsafe_block {
                in_unsafe_block = true;
                unsafe_start = line_num + 1;
                
                // Count opening braces
                if trimmed.contains('{') {
                    brace_count += trimmed.matches('{').count();
                }
            } else if in_unsafe_block {
                // Count braces to find the end of unsafe block
                brace_count += line.matches('{').count();
                brace_count = brace_count.saturating_sub(line.matches('}').count());
                
                if brace_count == 0 {
                    // Found the end of unsafe block
                    let unsafe_content = lines[unsafe_start - 1..line_num + 1].join("\n");
                    
                    unsafe_blocks.push(UnsafeBlockInfo {
                        line_start: unsafe_start,
                        line_end: line_num + 1,
                        content: unsafe_content,
                        context: self.get_context(&lines, unsafe_start, line_num + 1),
                    });
                    
                    in_unsafe_block = false;
                    brace_count = 0;
                }
            }
        }
        
        Ok(unsafe_blocks)
    }
    
    fn detect_unsafe_blocks(&self, content: &str, ast: &mut RustAst) -> Result<()> {
        // 线性扫描并计数花括号，定位 unsafe 代码块的起止行与上下文
        let lines: Vec<&str> = content.lines().collect();
        let mut in_unsafe_block = false;
        let mut unsafe_start = 0;
        let mut brace_count: usize = 0;
        
        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            
            if trimmed.starts_with("unsafe") && !in_unsafe_block {
                in_unsafe_block = true;
                unsafe_start = line_num + 1;
                
                // Count opening braces
                if trimmed.contains('{') {
                    brace_count += trimmed.matches('{').count();
                }
            } else if in_unsafe_block {
                // Count braces to find the end of unsafe block
                brace_count += line.matches('{').count();
                brace_count = brace_count.saturating_sub(line.matches('}').count());
                
                if brace_count == 0 {
                    // Found the end of unsafe block
                    let unsafe_content = lines[unsafe_start - 1..line_num + 1].join("\n");
                    
                    ast.unsafe_blocks.push(UnsafeBlockInfo {
                        line_start: unsafe_start,
                        line_end: line_num + 1,
                        content: unsafe_content,
                        context: self.get_context(&lines, unsafe_start, line_num + 1),
                    });
                    
                    in_unsafe_block = false;
                    brace_count = 0;
                }
            }
        }
        
        Ok(())
    }
    
    fn get_context(&self, lines: &[&str], start: usize, end: usize) -> String {
        // 提取 unsafe 块周围若干行作为上下文，便于报告展示
        let context_start = start.saturating_sub(3);
        let context_end = (end + 3).min(lines.len());
        
        lines[context_start..context_end].join("\n")
    }
    
    pub fn parse_code_snippet(&self, code: &str) -> Result<RustAst> {
        // 解析内联代码片段（非文件），用于快速实验与单元测试
        let syntax_tree = syn::parse_file(code)?;
        
        let mut ast = RustAst {
            file_path: "<snippet>".to_string(),
            syntax_tree,
            functions: Vec::new(),
            structs: Vec::new(),
            implementations: Vec::new(),
            traits: Vec::new(),
            enums: Vec::new(),
            unsafe_blocks: Vec::new(),
            lines_of_code: code.lines().count(),
        };
        
        // Clone the syntax tree to avoid borrowing issues
        let syntax_tree_clone = ast.syntax_tree.clone();
        self.extract_items(&syntax_tree_clone, &mut ast)?;
        
        if self.enable_unsafe_detection {
            // First detect unsafe blocks, then add them to ast
            let unsafe_blocks = self.find_unsafe_blocks(code)?;
            ast.unsafe_blocks = unsafe_blocks;
        }
        
        Ok(ast)
    }
}