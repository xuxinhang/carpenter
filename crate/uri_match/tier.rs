use std::collections::HashMap;
use std::iter::Iterator;


pub struct TierTree {
    nodes: Vec<TierNode>,
}


struct TierNode {
    star: bool,
    globstar: bool,
    accept: Option<usize>,
    next: HashMap<char, usize>,
}


impl TierTree {
    pub fn create_root() -> Self {
        let node = TierNode {
            star: false,
            globstar: true,
            accept: None,
            next: HashMap::new(),
        };
        Self {
            nodes: vec![node],
        }
    }

    pub fn insert(&mut self, char_iter: &mut impl Iterator<Item=char>, accept: usize) {
        let mut node_idx = 0;
        let mut char_pended = [None, None];

        loop {
            if char_pended[0].is_none() {
                let char_next = char_iter.next();
                if char_next.is_none() && char_pended[0].is_none() && char_pended[1].is_none() {
                    break;
                }
                char_pended = [char_pended[1], char_next];
            }

            match char_pended {
                // TODO: [Some('.'), Some('.')] => {
                [Some('*'), Some('*')] => {
                    self.nodes.get_mut(node_idx).unwrap().globstar = true;
                    char_pended = [None, None];
                }
                [Some('*'), _] => {
                    self.nodes.get_mut(node_idx).unwrap().star = true;
                    char_pended[0] = None;
                }
                [Some(c), _] => {
                    let node = self.nodes.get_mut(node_idx).unwrap();
                    if let Some(subnode_idx) = node.next.get(&c) {
                        node_idx = *subnode_idx;
                    } else {
                        let new_node = TierNode {
                            star: false,
                            globstar: false,
                            accept: None,
                            next: HashMap::new(),
                        };
                        self.nodes.push(new_node);
                        let subnode_idx = self.nodes.len() - 1;
                        let node = self.nodes.get_mut(node_idx).unwrap();
                        node.next.insert(c, subnode_idx);
                        node_idx = subnode_idx;
                    }
                    char_pended[0] = None;
                }
                _ => {}
            }
        }

        // while let Some(c) = char_iter.next() {
        //     match c {
        //         '*' => {
        //             self.nodes.get_mut(node_idx).unwrap().star = true;
        //         }
        //         _ => {
        //             let node = self.nodes.get_mut(node_idx).unwrap();
        //             if let Some(subnode_idx) = node.next.get(&c) {
        //                 node_idx = *subnode_idx;
        //             } else {
        //                 let new_node = TierNode { star: false, accept: None, next: HashMap::new() };
        //                 self.nodes.push(new_node);
        //                 let subnode_idx = self.nodes.len() - 1;
        //                 let node = self.nodes.get_mut(node_idx).unwrap();
        //                 node.next.insert(c, subnode_idx);
        //                 node_idx = subnode_idx;
        //             }
        //         }
        //     }
        // }

        self.nodes.get_mut(node_idx).unwrap().accept = Some(accept);
    }

    pub fn get(&self, chars: &mut impl Iterator<Item=char>) -> Vec<usize> {
        let mut points = vec![0];
        while let Some(c) = chars.next() {
            let point_number = points.len();
            let mut i = 0;
            while i < point_number {
                let node_idx = points.remove(0);
                let node = &self.nodes[node_idx];
                if node.globstar || (node.star && c != '.') {
                    points.push(node_idx);
                }
                if let Some(next_idx) = node.next.get(&c) {
                    points.push(*next_idx);
                }
                i += 1;
            }
            if points.is_empty() {
                break;
            }
        }

        return points.iter()
            .filter(|x| self.nodes[**x].accept.is_some())
            .map(|x| self.nodes[*x].accept.unwrap())
            .collect();
    }
}


pub struct HostMatchTree<P> {
    ports: HashMap<u16, TierTree>,
    profiles: Vec<(usize, P)>,
}

impl<P: Clone> HostMatchTree<P> {
    pub fn new() -> Self {
        Self {
            ports: HashMap::new(),
            profiles: Vec::new(),
        }
    }

    pub fn insert(&mut self, port: u16, hostname: &str, accept: P) {
        if self.ports.get(&port).is_none() {
            self.ports.insert(port, TierTree::create_root());
        }
        let hostname_char_count = hostname.chars().filter(|c| *c != '*').count();
        self.profiles.push((hostname_char_count, accept));
        let hostname_tree = self.ports.get_mut(&port).unwrap();

        let prof_idx = self.profiles.len() - 1;
        if hostname.len() >= 2 && &hostname[0..2] == ".."{
            let mut hostname = hostname.to_string();
            hostname.drain(0..2);
            hostname_tree.insert(&mut hostname.chars().rev().collect::<String>().chars(), prof_idx);
            hostname.insert_str(0, "**.");
            hostname_tree.insert(&mut hostname.chars().rev().collect::<String>().chars(), prof_idx);
        } else {
            hostname_tree.insert(&mut hostname.chars().rev().collect::<String>().chars(), prof_idx);
        }
    }

    pub fn get(&self, port: u16, hostname: &str) -> Option<P> {
        match self.ports.get(&port) {
            None => return None,
            Some(t) => {
                let mut search_pattern = hostname.chars().rev().collect::<String>();
                let mut final_profile = None;
                let mut final_prof_score: isize = -1;

                search_pattern.push('.');
                let accept_idx = t.get(&mut search_pattern.chars());
                if !accept_idx.is_empty() {
                    let i = accept_idx.iter().max_by_key(|x| self.profiles[**x].0).unwrap();
                    final_prof_score = self.profiles[*i].0 as isize - 1;
                    final_profile = Some(self.profiles[*i].1.clone());
                }

                search_pattern.pop();
                let accept_idx = t.get(&mut search_pattern.chars());
                if !accept_idx.is_empty() {
                    let i = accept_idx.iter().max_by_key(|x| self.profiles[**x].0).unwrap();
                    if final_prof_score <= self.profiles[*i].0 as isize {
                        final_profile = Some(self.profiles[*i].1.clone());
                    }
                }

                return final_profile;
            }
        };
    }
}
