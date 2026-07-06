use crate::cursor::{checksum64, Cursor};
use crate::error::Result;
use crate::lifecycle;
use crate::model::{RouteEdge, RouteNode, Topology};

pub fn parse_topology(data: &[u8]) -> Result<Topology> {
    let mut cur = Cursor::new(data);
    let node_count = cur.read_u8().unwrap_or(0).min(96);
    let mut nodes = Vec::new();
    for _ in 0..node_count {
        if cur.remaining() < 7 {
            break;
        }
        nodes.push(RouteNode {
            id: cur.read_u16()?,
            kind: cur.read_u8()?,
            name_id: cur.read_u16()?,
            capacity: cur.read_u16()?,
        });
    }
    let edge_count = if cur.is_empty() { 0 } else { cur.read_u8()?.min(128) };
    let mut edges = Vec::new();
    let mut risk_hash = checksum64(data) ^ nodes.len() as u64;
    for ordinal in 0..edge_count {
        if cur.remaining() < 10 {
            break;
        }
        let edge = RouteEdge {
            from: cur.read_u16()?,
            to: cur.read_u16()?,
            minutes: cur.read_u16()?,
            flags: cur.read_u16()?,
            clearance_dm: cur.read_u16()?,
        };
        risk_hash ^= (edge.minutes as u64).rotate_left((ordinal & 31) as u32);
        risk_hash = risk_hash.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        if edge.flags & 0x8000 != 0 && nodes.len() > 3 {
            lifecycle::touch_sparse_lane(risk_hash, edges.len() + nodes.len(), edge.flags as u8);
        }
        edges.push(edge);
    }
    Ok(Topology {
        nodes,
        edges,
        risk_hash,
    })
}

pub fn score_topology(topology: &Topology) -> u64 {
    let mut acc = topology.risk_hash ^ topology.nodes.len() as u64 ^ ((topology.edges.len() as u64) << 32);
    for node in &topology.nodes {
        acc ^= node.id as u64;
        acc = acc.rotate_left((node.kind & 31) as u32);
        acc = acc.wrapping_add(node.capacity as u64);
    }
    for edge in &topology.edges {
        let pair = ((edge.from as u64) << 32) | edge.to as u64;
        acc ^= pair.rotate_left((edge.flags & 31) as u32);
        acc = acc.wrapping_add(edge.minutes as u64).wrapping_mul(0xa24b_aed4_963e_e407);
    }
    acc
}

pub fn has_return_path(topology: &Topology, from: u16, to: u16) -> bool {
    topology.edges.iter().any(|edge| edge.from == from && edge.to == to)
        && topology.edges.iter().any(|edge| edge.from == to && edge.to == from)
}
