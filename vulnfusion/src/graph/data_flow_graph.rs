// 中文说明：
// DataFlowGraph 描述变量定义/使用、Phi、调用与返回等数据流节点及依赖边，
// 支持 def-use/use-def 链、存活性与常量传播机会识别，服务路径敏感分析。
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;

pub struct DataFlowGraph {
    graph: DiGraph<DataFlowNode, DataFlowEdge>,
    def_use_chains: HashMap<NodeIndex, Vec<Use>>,
    use_def_chains: HashMap<NodeIndex, Vec<Definition>>,
}

#[derive(Debug, Clone)]
pub struct DataFlowNode {
    pub id: String,
    pub kind: DataFlowNodeKind,
    pub ty: String,
    pub scope: String,
    pub line_number: usize,
}

#[derive(Debug, Clone)]
pub enum DataFlowNodeKind {
    Definition {
        variable: String,
        value: Option<String>,
        is_mutable: bool,
    },
    Use {
        variable: String,
        usage_type: UsageType,
    },
    Phi {
        variables: Vec<String>,
    },
    Call {
        function: String,
        arguments: Vec<String>,
        return_value: Option<String>,
    },
    Return {
        value: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub enum UsageType {
    Read,
    Write,
    Borrow,
    Move,
}

#[derive(Debug, Clone)]
pub struct DataFlowEdge {
    pub edge_type: DataFlowEdgeType,
    pub label: Option<String>,
}

#[derive(Debug, Clone)]
pub enum DataFlowEdgeType {
    DataDependency,
    ControlDependency,
    DefUse,
    UseDef,
}

#[derive(Debug, Clone)]
pub struct Definition {
    pub node: NodeIndex,
    pub variable: String,
    pub scope: String,
}

#[derive(Debug, Clone)]
pub struct Use {
    pub node: NodeIndex,
    pub variable: String,
    pub usage_type: UsageType,
}

impl DataFlowGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            def_use_chains: HashMap::new(),
            use_def_chains: HashMap::new(),
        }
    }
    
    pub fn add_node(&mut self, node: DataFlowNode) -> NodeIndex {
        let node_idx = self.graph.add_node(node.clone());
        
        match &node.kind {
            DataFlowNodeKind::Definition { variable, .. } => {
                self.def_use_chains.insert(node_idx, Vec::new());
            }
            DataFlowNodeKind::Use { variable, usage_type } => {
                let usage = Use {
                    node: node_idx,
                    variable: variable.clone(),
                    usage_type: usage_type.clone(),
                };
                self.use_def_chains.insert(node_idx, Vec::new());
                
                // Find corresponding definitions
                self.update_def_use_chains(&usage);
            }
            _ => {}
        }
        
        node_idx
    }
    
    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, edge: DataFlowEdge) {
        self.graph.add_edge(from, to, edge);
    }
    
    fn update_def_use_chains(&mut self, usage: &Use) {
        // Find all definitions of the variable that reach this use
        let reaching_definitions = self.find_reaching_definitions(usage);
        
        for def in reaching_definitions {
            // Add use to definition's use chain
            if let Some(uses) = self.def_use_chains.get_mut(&def.node) {
                uses.push(usage.clone());
            }
            
            // Add definition to use's definition chain
            if let Some(defs) = self.use_def_chains.get_mut(&usage.node) {
                defs.push(def);
            }
        }
    }
    
    fn find_reaching_definitions(&self, usage: &Use) -> Vec<Definition> {
        let mut definitions = Vec::new();
        
        // Simple reaching definitions analysis
        // In a real implementation, this would be more sophisticated
        for node_idx in self.graph.node_indices() {
            if let Some(node) = self.graph.node_weight(node_idx) {
                if let DataFlowNodeKind::Definition { variable, .. } = &node.kind {
                    if variable == &usage.variable {
                        definitions.push(Definition {
                            node: node_idx,
                            variable: variable.clone(),
                            scope: node.scope.clone(),
                        });
                    }
                }
            }
        }
        
        definitions
    }
    
    pub fn get_def_use_chain(&self, definition: NodeIndex) -> Option<&Vec<Use>> {
        self.def_use_chains.get(&definition)
    }
    
    pub fn get_use_def_chain(&self, usage: NodeIndex) -> Option<&Vec<Definition>> {
        self.use_def_chains.get(&usage)
    }
    
    pub fn find_data_flow_path(&self, from: NodeIndex, to: NodeIndex) -> Option<Vec<NodeIndex>> {
        // Simple path finding using DFS
        let mut visited = std::collections::HashSet::new();
        let mut path = Vec::new();
        
        if self.dfs_find_path(from, to, &mut visited, &mut path) {
            Some(path)
        } else {
            None
        }
    }
    
    fn dfs_find_path(
        &self,
        current: NodeIndex,
        target: NodeIndex,
        visited: &mut std::collections::HashSet<NodeIndex>,
        path: &mut Vec<NodeIndex>,
    ) -> bool {
        if current == target {
            path.push(current);
            return true;
        }
        
        if visited.contains(&current) {
            return false;
        }
        
        visited.insert(current);
        path.push(current);
        
        for neighbor in self.graph.neighbors(current) {
            if self.dfs_find_path(neighbor, target, visited, path) {
                return true;
            }
        }
        
        path.pop();
        false
    }
    
    pub fn perform_liveness_analysis(&self) -> HashMap<NodeIndex, bool> {
        let mut live_vars = HashMap::new();
        
        // Simple liveness analysis
        // A variable is live if it has a use that is reachable from its definition
        for node_idx in self.graph.node_indices() {
            if let Some(node) = self.graph.node_weight(node_idx) {
                if let DataFlowNodeKind::Definition { variable, .. } = &node.kind {
                    let is_live = self.is_variable_live(node_idx, variable);
                    live_vars.insert(node_idx, is_live);
                }
            }
        }
        
        live_vars
    }
    
    fn is_variable_live(&self, definition: NodeIndex, variable: &str) -> bool {
        // Check if there's a path from definition to a use of the variable
        if let Some(uses) = self.def_use_chains.get(&definition) {
            for usage in uses {
                if let Some(node) = self.graph.node_weight(usage.node) {
                    if let DataFlowNodeKind::Use { variable: used_var, .. } = &node.kind {
                        if used_var == variable {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
    
    pub fn find_constant_propagation_opportunities(&self) -> Vec<ConstantPropagationOpportunity> {
        let mut opportunities = Vec::new();
        
        // Look for definitions with constant values that are used
        for node_idx in self.graph.node_indices() {
            if let Some(node) = self.graph.node_weight(node_idx) {
                if let DataFlowNodeKind::Definition { variable, value: Some(val), .. } = &node.kind {
                    if self.is_constant_value(val) {
                        if let Some(uses) = self.def_use_chains.get(&node_idx) {
                            for usage in uses {
                                opportunities.push(ConstantPropagationOpportunity {
                                    definition: node_idx,
                                    usage: usage.node,
                                    variable: variable.clone(),
                                    constant_value: val.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }
        
        opportunities
    }
    
    fn is_constant_value(&self, value: &str) -> bool {
        // Simple constant detection
        value.parse::<i64>().is_ok() || 
        value.parse::<f64>().is_ok() || 
        value == "true" || 
        value == "false" ||
        value.starts_with('"') && value.ends_with('"')
    }
}

#[derive(Debug, Clone)]
pub struct ConstantPropagationOpportunity {
    pub definition: NodeIndex,
    pub usage: NodeIndex,
    pub variable: String,
    pub constant_value: String,
}

impl Default for DataFlowGraph {
    fn default() -> Self {
        Self::new()
    }
}