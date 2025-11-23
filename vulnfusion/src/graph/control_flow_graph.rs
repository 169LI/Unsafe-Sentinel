// 中文说明：
// ControlFlowGraph 以基本块为节点构建控制流图，支持入口/出口块、支配关系与
// 回边（循环）检测等基础分析，服务于 panic 传播与越界路径等推断。
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;

pub struct ControlFlowGraph {
    graph: DiGraph<BasicBlock, ControlFlowEdge>,
    entry_block: Option<NodeIndex>,
    exit_blocks: Vec<NodeIndex>,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: usize,
    pub statements: Vec<String>,
    pub terminator: Option<String>,
    pub is_loop_header: bool,
    pub is_loop_latch: bool,
    pub dominators: Vec<usize>,
}

#[derive(Debug, Clone)]
pub enum ControlFlowEdge {
    Unconditional,
    Conditional(bool), // true for then branch, false for else branch
    LoopBack,
    Exception,
    Return,
}

impl ControlFlowGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            entry_block: None,
            exit_blocks: Vec::new(),
        }
    }
    
    pub fn add_basic_block(&mut self, block: BasicBlock) -> NodeIndex {
        let node_idx = self.graph.add_node(block.clone());
        
        if self.entry_block.is_none() {
            self.entry_block = Some(node_idx);
        }
        
        if block.terminator.as_ref().map(|t| t.contains("return")).unwrap_or(false) {
            self.exit_blocks.push(node_idx);
        }
        
        node_idx
    }
    
    pub fn add_control_flow_edge(&mut self, from: NodeIndex, to: NodeIndex, edge: ControlFlowEdge) {
        self.graph.add_edge(from, to, edge);
    }
    
    pub fn get_entry_block(&self) -> Option<NodeIndex> {
        self.entry_block
    }
    
    pub fn get_exit_blocks(&self) -> &[NodeIndex] {
        &self.exit_blocks
    }
    
    pub fn find_dominators(&self) -> HashMap<NodeIndex, Vec<NodeIndex>> {
        // Simple dominator analysis
        let mut dominators = HashMap::new();
        
        if let Some(entry) = self.entry_block {
            let all_nodes: Vec<NodeIndex> = self.graph.node_indices().collect();
            
            for &node in &all_nodes {
                if node == entry {
                    dominators.insert(node, vec![entry]);
                } else {
                    dominators.insert(node, all_nodes.clone());
                }
            }
            
            // Iterative dominator computation
            let mut changed = true;
            while changed {
                changed = false;
                
                for &node in &all_nodes {
                    if node == entry {
                        continue;
                    }
                    
                    let predecessors: Vec<NodeIndex> = self.graph
                        .neighbors_directed(node, petgraph::Direction::Incoming)
                        .collect();
                    
                    if !predecessors.is_empty() {
                        let mut new_dominators = if let Some(&first_pred) = predecessors.first() {
                            dominators.get(&first_pred).cloned().unwrap_or_default()
                        } else {
                            Vec::new()
                        };
                        
                        for &pred in &predecessors[1..] {
                            let pred_dominators = dominators.get(&pred).cloned().unwrap_or_default();
                            new_dominators.retain(|&d| pred_dominators.contains(&d));
                        }
                        
                        new_dominators.push(node);
                        new_dominators.sort();
                        new_dominators.dedup();
                        
                        if dominators.get(&node) != Some(&new_dominators) {
                            dominators.insert(node, new_dominators);
                            changed = true;
                        }
                    }
                }
            }
        }
        
        dominators
    }
    
    pub fn find_loops(&self) -> Vec<LoopInfo> {
        let mut loops = Vec::new();
        let dominators = self.find_dominators();
        
        for edge in self.graph.edge_indices() {
            if let Some((source, target)) = self.graph.edge_endpoints(edge) {
                if let Some(dom_list) = dominators.get(&target) {
                    if dom_list.contains(&source) {
                        // Found a back edge, indicating a loop
                        let loop_info = LoopInfo {
                            header: target,
                            latch: source,
                            blocks: self.find_loop_blocks(target, source),
                        };
                        loops.push(loop_info);
                    }
                }
            }
        }
        
        loops
    }
    
    fn find_loop_blocks(&self, header: NodeIndex, latch: NodeIndex) -> Vec<NodeIndex> {
        // Find all blocks that are reachable from the header and can reach the latch
        let mut loop_blocks = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut stack = vec![header];
        
        while let Some(current) = stack.pop() {
            if visited.contains(&current) {
                continue;
            }
            
            visited.insert(current);
            loop_blocks.push(current);
            
            // Check if we can reach the latch from this block
            if self.can_reach(current, latch, &visited) {
                // Add successors
                for successor in self.graph.neighbors_directed(current, petgraph::Direction::Outgoing) {
                    if !visited.contains(&successor) {
                        stack.push(successor);
                    }
                }
            }
        }
        
        loop_blocks
    }
    
    fn can_reach(&self, from: NodeIndex, to: NodeIndex, visited: &std::collections::HashSet<NodeIndex>) -> bool {
        if from == to {
            return true;
        }
        
        let mut stack = vec![from];
        let mut local_visited = visited.clone();
        
        while let Some(current) = stack.pop() {
            if current == to {
                return true;
            }
            
            if local_visited.contains(&current) {
                continue;
            }
            
            local_visited.insert(current);
            
            for successor in self.graph.neighbors_directed(current, petgraph::Direction::Outgoing) {
                if !local_visited.contains(&successor) {
                    stack.push(successor);
                }
            }
        }
        
        false
    }
    
    pub fn get_dominance_frontier(&self) -> HashMap<NodeIndex, Vec<NodeIndex>> {
        let dominators = self.find_dominators();
        let mut dominance_frontier = HashMap::new();
        
        for node in self.graph.node_indices() {
            dominance_frontier.insert(node, Vec::new());
        }
        
        for node in self.graph.node_indices() {
            let predecessors: Vec<NodeIndex> = self.graph
                .neighbors_directed(node, petgraph::Direction::Incoming)
                .collect();
            
            if predecessors.len() >= 2 {
                for &pred in &predecessors {
                    let mut runner = pred;
                    
                    while let Some(dom_list) = dominators.get(&node) {
                        if !dom_list.contains(&runner) && runner != node {
                            if let Some(df) = dominance_frontier.get_mut(&runner) {
                                if !df.contains(&node) {
                                    df.push(node);
                                }
                            }
                            
                            // Move up the dominator tree
                            if let Some(pred_of_runner) = self.graph
                                .neighbors_directed(runner, petgraph::Direction::Incoming)
                                .next() {
                                runner = pred_of_runner;
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }
        
        dominance_frontier
    }
}

#[derive(Debug, Clone)]
pub struct LoopInfo {
    pub header: NodeIndex,
    pub latch: NodeIndex,
    pub blocks: Vec<NodeIndex>,
}

impl Default for ControlFlowGraph {
    fn default() -> Self {
        Self::new()
    }
}