// 中文说明：
// AnalysisGraph 使用有向图表达函数/结构体/trait/impl/unsafe 块等元素及其关系，
// 构建调用、所有权与不安全依赖等边，为检测器提供图基础数据与统计能力。
use crate::utils::error::Result;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;
use quote::ToTokens;
use crate::parser::RustAst;

pub struct AnalysisGraph {
    graph: DiGraph<GraphNode, GraphEdge>,
    node_map: HashMap<String, NodeIndex>,
}

#[derive(Debug, Clone)]
pub enum GraphNode {
    Function {
        name: String,
        signature: String,
        is_unsafe: bool,
        is_async: bool,
        visibility: String,
    },
    Struct {
        name: String,
        fields: Vec<String>,
        visibility: String,
    },
    Trait {
        name: String,
        methods: Vec<String>,
        visibility: String,
    },
    Impl {
        target: String,
        trait_name: Option<String>,
        methods: Vec<String>,
    },
    UnsafeBlock {
        id: String,
        line_start: usize,
        line_end: usize,
        operations: Vec<String>,
    },
    Variable {
        name: String,
        ty: String,
        scope: String,
        is_mutable: bool,
    },
    Call {
        function_name: String,
        arguments: Vec<String>,
        is_unsafe: bool,
    },
}

#[derive(Debug, Clone)]
pub enum GraphEdge {
    Calls,
    References,
    Owns,
    Borrows,
    Implements,
    Contains,
    DependsOn,
    UnsafeDependency,
}

impl AnalysisGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
        }
    }
    
    pub fn build_from_ast(&mut self, ast: &RustAst) -> Result<()> {
        // Add nodes for different AST elements
        self.add_function_nodes(ast)?;
        self.add_struct_nodes(ast)?;
        self.add_trait_nodes(ast)?;
        self.add_impl_nodes(ast)?;
        self.add_unsafe_block_nodes(ast)?;
        
        // Add edges to represent relationships
        self.add_call_edges(ast)?;
        self.add_ownership_edges(ast)?;
        self.add_unsafe_dependency_edges(ast)?;
        
        Ok(())
    }
    
    fn add_function_nodes(&mut self, ast: &RustAst) -> Result<()> {
        for func in &ast.functions {
            let func_name = func.sig.ident.to_string();
            let signature = func.sig.to_token_stream().to_string();
            let is_unsafe = func.sig.unsafety.is_some();
            let is_async = func.sig.asyncness.is_some();
            let visibility = Self::extract_visibility(&func.vis);
            
            let node = GraphNode::Function {
                name: func_name.clone(),
                signature,
                is_unsafe,
                is_async,
                visibility,
            };
            
            let node_idx = self.graph.add_node(node);
            self.node_map.insert(format!("fn:{}", func_name), node_idx);
        }
        
        Ok(())
    }
    
    fn add_struct_nodes(&mut self, ast: &RustAst) -> Result<()> {
        for strct in &ast.structs {
            let struct_name = strct.ident.to_string();
            let visibility = Self::extract_visibility(&strct.vis);
            
            let fields = strct.fields.iter()
                .filter_map(|field| field.ident.as_ref().map(|id| id.to_string()))
                .collect();
            
            let node = GraphNode::Struct {
                name: struct_name.clone(),
                fields,
                visibility,
            };
            
            let node_idx = self.graph.add_node(node);
            self.node_map.insert(format!("struct:{}", struct_name), node_idx);
        }
        
        Ok(())
    }
    
    fn add_trait_nodes(&mut self, ast: &RustAst) -> Result<()> {
        for trait_item in &ast.traits {
            let trait_name = trait_item.ident.to_string();
            let visibility = Self::extract_visibility(&trait_item.vis);
            
            let methods = trait_item.items.iter()
                .filter_map(|item| {
                    if let syn::TraitItem::Fn(method) = item {
                        Some(method.sig.ident.to_string())
                    } else {
                        None
                    }
                })
                .collect();
            
            let node = GraphNode::Trait {
                name: trait_name.clone(),
                methods,
                visibility,
            };
            
            let node_idx = self.graph.add_node(node);
            self.node_map.insert(format!("trait:{}", trait_name), node_idx);
        }
        
        Ok(())
    }
    
    fn add_impl_nodes(&mut self, ast: &RustAst) -> Result<()> {
        for impl_block in &ast.implementations {
            let target = Self::extract_type_name(&impl_block.self_ty);
            let trait_name = impl_block.trait_.as_ref()
                .map(|(_, path, _)| Self::extract_path_name(path));
            
            let methods = impl_block.items.iter()
                .filter_map(|item| {
                    if let syn::ImplItem::Fn(method) = item {
                        Some(method.sig.ident.to_string())
                    } else {
                        None
                    }
                })
                .collect();
            
            let node = GraphNode::Impl {
                target: target.clone(),
                trait_name: trait_name.clone(),
                methods,
            };
            
            let node_idx = self.graph.add_node(node);
            let node_id = if let Some(trait_name) = trait_name {
                format!("impl:{}:{}", target, trait_name)
            } else {
                format!("impl:{}", target)
            };
            self.node_map.insert(node_id, node_idx);
        }
        
        Ok(())
    }
    
    fn add_unsafe_block_nodes(&mut self, ast: &RustAst) -> Result<()> {
        for (i, unsafe_block) in ast.unsafe_blocks.iter().enumerate() {
            let operations = Self::extract_unsafe_operations(&unsafe_block.content);
            
            let node = GraphNode::UnsafeBlock {
                id: format!("unsafe_{}", i),
                line_start: unsafe_block.line_start,
                line_end: unsafe_block.line_end,
                operations,
            };
            
            let node_idx = self.graph.add_node(node);
            self.node_map.insert(format!("unsafe:{}", i), node_idx);
        }
        
        Ok(())
    }
    
    fn add_call_edges(&mut self, ast: &RustAst) -> Result<()> {
        // This is a simplified implementation
        // In a real implementation, you would analyze the function bodies
        // to find actual function calls
        
        for func in &ast.functions {
            let func_name = func.sig.ident.to_string();
            let func_node_id = format!("fn:{}", func_name);
            
            if let Some(&func_idx) = self.node_map.get(&func_node_id) {
                // Look for calls to other functions in the same file
                let func_code = func.to_token_stream().to_string();
                
                for other_func in &ast.functions {
                    let other_name = other_func.sig.ident.to_string();
                    if other_name != func_name && func_code.contains(&other_name) {
                        let other_node_id = format!("fn:{}", other_name);
                        if let Some(&other_idx) = self.node_map.get(&other_node_id) {
                            self.graph.add_edge(func_idx, other_idx, GraphEdge::Calls);
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    fn add_ownership_edges(&mut self, ast: &RustAst) -> Result<()> {
        // Add ownership relationships between structs and their fields
        for strct in &ast.structs {
            let struct_name = strct.ident.to_string();
            let struct_node_id = format!("struct:{}", struct_name);
            
            if let Some(&struct_idx) = self.node_map.get(&struct_node_id) {
                // Add ownership edges to field types
                for field in &strct.fields {
                    if let syn::Type::Path(type_path) = &field.ty {
                        let field_type = Self::extract_path_name(&type_path.path);
                        let field_node_id = format!("struct:{}", field_type);
                        
                        if let Some(&field_idx) = self.node_map.get(&field_node_id) {
                            self.graph.add_edge(struct_idx, field_idx, GraphEdge::Owns);
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    fn add_unsafe_dependency_edges(&mut self, ast: &RustAst) -> Result<()> {
        // Mark functions that call unsafe blocks as having unsafe dependencies
        for func in &ast.functions {
            let func_name = func.sig.ident.to_string();
            let func_node_id = format!("fn:{}", func_name);
            
            if let Some(&func_idx) = self.node_map.get(&func_node_id) {
                let func_code = func.to_token_stream().to_string();
                
                // Check if function contains unsafe blocks
                if func_code.contains("unsafe") {
                    // Find unsafe block nodes and create dependency edges
                    for (i, unsafe_block) in ast.unsafe_blocks.iter().enumerate() {
                        if func_code.contains(&unsafe_block.content) {
                            let unsafe_node_id = format!("unsafe:{}", i);
                            if let Some(&unsafe_idx) = self.node_map.get(&unsafe_node_id) {
                                self.graph.add_edge(func_idx, unsafe_idx, GraphEdge::UnsafeDependency);
                            }
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    fn extract_visibility(vis: &syn::Visibility) -> String {
        match vis {
            syn::Visibility::Public(_) => "pub".to_string(),
            syn::Visibility::Restricted(_) => "pub(restricted)".to_string(),
            syn::Visibility::Inherited => "private".to_string(),
        }
    }
    
    fn extract_type_name(ty: &syn::Type) -> String {
        match ty {
            syn::Type::Path(type_path) => Self::extract_path_name(&type_path.path),
            _ => "unknown".to_string(),
        }
    }
    
    fn extract_path_name(path: &syn::Path) -> String {
        path.segments.last()
            .map(|seg| seg.ident.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }
    
    fn extract_unsafe_operations(content: &str) -> Vec<String> {
        let mut operations = Vec::new();
        
        // Look for common unsafe operations
        let unsafe_patterns = [
            "*const", "*mut", "ptr::", "mem::", "transmute",
            "get_unchecked", "offset", "add", "sub",
        ];
        
        for pattern in &unsafe_patterns {
            if content.contains(pattern) {
                operations.push(pattern.to_string());
            }
        }
        
        operations
    }
    
    pub fn get_node(&self, node_id: &str) -> Option<&GraphNode> {
        self.node_map.get(node_id)
            .and_then(|&idx| self.graph.node_weight(idx))
    }
    
    pub fn get_neighbors(&self, node_id: &str) -> Vec<&GraphNode> {
        if let Some(&idx) = self.node_map.get(node_id) {
            self.graph.neighbors(idx)
                .filter_map(|neighbor_idx| self.graph.node_weight(neighbor_idx))
                .collect()
        } else {
            Vec::new()
        }
    }
    
    pub fn find_path(&self, from: &str, to: &str) -> Option<Vec<String>> {
        use petgraph::algo::dijkstra;
        
        let from_idx = self.node_map.get(from)?;
        let to_idx = self.node_map.get(to)?;
        
        let path_map = dijkstra(&self.graph, *from_idx, Some(*to_idx), |_| 1);
        
        if path_map.contains_key(to_idx) {
            // Reconstruct path (simplified)
            Some(vec![from.to_string(), to.to_string()])
        } else {
            None
        }
    }
    
    pub fn get_statistics(&self) -> GraphStatistics {
        GraphStatistics {
            total_nodes: self.graph.node_count(),
            total_edges: self.graph.edge_count(),
            function_nodes: self.count_nodes_by_type(|node| matches!(node, GraphNode::Function { .. })),
            struct_nodes: self.count_nodes_by_type(|node| matches!(node, GraphNode::Struct { .. })),
            trait_nodes: self.count_nodes_by_type(|node| matches!(node, GraphNode::Trait { .. })),
            unsafe_nodes: self.count_nodes_by_type(|node| matches!(node, GraphNode::UnsafeBlock { .. })),
        }
    }
    
    fn count_nodes_by_type<F>(&self, predicate: F) -> usize
    where
        F: Fn(&GraphNode) -> bool,
    {
        self.graph.node_weights().filter(|node| predicate(node)).count()
    }
}

#[derive(Debug)]
pub struct GraphStatistics {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub function_nodes: usize,
    pub struct_nodes: usize,
    pub trait_nodes: usize,
    pub unsafe_nodes: usize,
}