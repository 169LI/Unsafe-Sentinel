// 中文说明：
// CallGraph 构建函数到函数的调用关系图，支持计算可达性、入口/叶子函数、
// 递归与环路等统计信息，为并发/panic 等跨过程分析提供基础。
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{HashMap, HashSet};

pub struct CallGraph {
    graph: DiGraph<CallGraphNode, CallGraphEdge>,
    function_map: HashMap<String, NodeIndex>,
}

#[derive(Debug, Clone)]
pub struct CallGraphNode {
    pub function_name: String,
    pub signature: String,
    pub is_unsafe: bool,
    pub is_generic: bool,
    pub visibility: String,
    pub module_path: String,
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CallGraphEdge {
    pub call_type: CallType,
    pub call_site: Option<SourceLocation>,
    pub is_dynamic: bool,
}

#[derive(Debug, Clone)]
pub enum CallType {
    Direct,
    Indirect,
    Virtual,
    TraitMethod,
    Closure,
    Macro,
}

#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

impl CallGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            function_map: HashMap::new(),
        }
    }
    
    pub fn add_function(&mut self, node: CallGraphNode) -> NodeIndex {
        let node_idx = self.graph.add_node(node.clone());
        self.function_map.insert(node.function_name.clone(), node_idx);
        node_idx
    }
    
    pub fn add_call(&mut self, caller: &str, callee: &str, edge: CallGraphEdge) -> Result<(), CallGraphError> {
        let caller_idx = self.function_map.get(caller)
            .ok_or(CallGraphError::FunctionNotFound(caller.to_string()))?;
        
        let callee_idx = self.function_map.get(callee)
            .ok_or(CallGraphError::FunctionNotFound(callee.to_string()))?;
        
        self.graph.add_edge(*caller_idx, *callee_idx, edge);
        Ok(())
    }
    
    pub fn find_reachable_functions(&self, start: &str) -> Result<HashSet<String>, CallGraphError> {
        let start_idx = self.function_map.get(start)
            .ok_or(CallGraphError::FunctionNotFound(start.to_string()))?;
        
        let mut reachable = HashSet::new();
        let mut stack = vec![*start_idx];
        let mut visited = HashSet::new();
        
        while let Some(current) = stack.pop() {
            if visited.contains(&current) {
                continue;
            }
            
            visited.insert(current);
            
            if let Some(node) = self.graph.node_weight(current) {
                reachable.insert(node.function_name.clone());
                
                // Add successors
                for neighbor in self.graph.neighbors(current) {
                    if !visited.contains(&neighbor) {
                        stack.push(neighbor);
                    }
                }
            }
        }
        
        Ok(reachable)
    }
    
    pub fn find_callers(&self, function: &str) -> Result<Vec<String>, CallGraphError> {
        let function_idx = self.function_map.get(function)
            .ok_or(CallGraphError::FunctionNotFound(function.to_string()))?;
        
        let mut callers = Vec::new();
        
        for predecessor in self.graph.neighbors_directed(*function_idx, petgraph::Direction::Incoming) {
            if let Some(node) = self.graph.node_weight(predecessor) {
                callers.push(node.function_name.clone());
            }
        }
        
        Ok(callers)
    }
    
    pub fn find_callees(&self, function: &str) -> Result<Vec<String>, CallGraphError> {
        let function_idx = self.function_map.get(function)
            .ok_or(CallGraphError::FunctionNotFound(function.to_string()))?;
        
        let mut callees = Vec::new();
        
        for successor in self.graph.neighbors_directed(*function_idx, petgraph::Direction::Outgoing) {
            if let Some(node) = self.graph.node_weight(successor) {
                callees.push(node.function_name.clone());
            }
        }
        
        Ok(callees)
    }
    
    pub fn find_recursive_functions(&self) -> Vec<String> {
        let mut recursive = Vec::new();
        
        for (function_name, &node_idx) in &self.function_map {
            if self.is_recursive(node_idx) {
                recursive.push(function_name.clone());
            }
        }
        
        recursive
    }
    
    fn is_recursive(&self, start: NodeIndex) -> bool {
        let mut visited = HashSet::new();
        let mut stack = vec![start];
        
        while let Some(current) = stack.pop() {
            if current == start && visited.contains(&current) {
                return true;
            }
            
            if visited.contains(&current) {
                continue;
            }
            
            visited.insert(current);
            
            for neighbor in self.graph.neighbors(current) {
                stack.push(neighbor);
            }
        }
        
        false
    }
    
    pub fn find_cycles(&self) -> Vec<Vec<String>> {
        let mut cycles = Vec::new();
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        let mut path = Vec::new();
        
        for node_idx in self.graph.node_indices() {
            if !visited.contains(&node_idx) {
                self.find_cycles_dfs(node_idx, &mut visited, &mut rec_stack, &mut path, &mut cycles);
            }
        }
        
        cycles
    }
    
    fn find_cycles_dfs(
        &self,
        node: NodeIndex,
        visited: &mut HashSet<NodeIndex>,
        rec_stack: &mut HashSet<NodeIndex>,
        path: &mut Vec<NodeIndex>,
        cycles: &mut Vec<Vec<String>>,
    ) {
        visited.insert(node);
        rec_stack.insert(node);
        path.push(node);
        
        for neighbor in self.graph.neighbors(node) {
            if !visited.contains(&neighbor) {
                self.find_cycles_dfs(neighbor, visited, rec_stack, path, cycles);
            } else if rec_stack.contains(&neighbor) {
                // Found a cycle
                let cycle_start = path.iter().position(|&n| n == neighbor).unwrap();
                let cycle: Vec<String> = path[cycle_start..]
                    .iter()
                    .filter_map(|&n| self.graph.node_weight(n))
                    .map(|node| node.function_name.clone())
                    .collect();
                
                if !cycle.is_empty() {
                    cycles.push(cycle);
                }
            }
        }
        
        rec_stack.remove(&node);
        path.pop();
    }
    
    pub fn get_entry_points(&self) -> Vec<String> {
        let mut entry_points = Vec::new();
        
        for node_idx in self.graph.node_indices() {
            let has_incoming = self.graph
                .neighbors_directed(node_idx, petgraph::Direction::Incoming)
                .count() > 0;
            
            if !has_incoming {
                if let Some(node) = self.graph.node_weight(node_idx) {
                    entry_points.push(node.function_name.clone());
                }
            }
        }
        
        entry_points
    }
    
    pub fn get_leaf_functions(&self) -> Vec<String> {
        let mut leaf_functions = Vec::new();
        
        for node_idx in self.graph.node_indices() {
            let has_outgoing = self.graph
                .neighbors_directed(node_idx, petgraph::Direction::Outgoing)
                .count() > 0;
            
            if !has_outgoing {
                if let Some(node) = self.graph.node_weight(node_idx) {
                    leaf_functions.push(node.function_name.clone());
                }
            }
        }
        
        leaf_functions
    }
    
    pub fn get_statistics(&self) -> CallGraphStatistics {
        let total_functions = self.graph.node_count();
        let total_calls = self.graph.edge_count();
        let recursive_functions = self.find_recursive_functions().len();
        let cycles = self.find_cycles().len();
        let entry_points = self.get_entry_points().len();
        let leaf_functions = self.get_leaf_functions().len();
        
        CallGraphStatistics {
            total_functions,
            total_calls,
            recursive_functions,
            cycles,
            entry_points,
            leaf_functions,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CallGraphStatistics {
    pub total_functions: usize,
    pub total_calls: usize,
    pub recursive_functions: usize,
    pub cycles: usize,
    pub entry_points: usize,
    pub leaf_functions: usize,
}

#[derive(Debug, Clone)]
pub enum CallGraphError {
    FunctionNotFound(String),
    CycleDetected(Vec<String>),
}

impl std::fmt::Display for CallGraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallGraphError::FunctionNotFound(name) => write!(f, "Function not found: {}", name),
            CallGraphError::CycleDetected(cycle) => {
                write!(f, "Cycle detected: {}", cycle.join(" -> "))
            }
        }
    }
}

impl std::error::Error for CallGraphError {}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}