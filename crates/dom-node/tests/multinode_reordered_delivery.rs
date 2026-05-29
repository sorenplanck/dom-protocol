use dom_node::missing_block_tracker::MissingBlockTracker;
use dom_node::orphan_pool::{OrphanBlock, OrphanInsertOutcome, RuntimeOrphanPool};

fn h(seed: u8) -> [u8; 32] {
    let mut x = [0u8; 32];
    x[0] = seed;
    x
}

fn orphan(child: u8, parent: u8, height: u64) -> OrphanBlock {
    OrphanBlock {
        block_hash: h(child),
        parent_hash: h(parent),
        height,
        block_bytes: vec![child],
    }
}

struct HarnessNode {
    tip: [u8; 32],
    tracker: MissingBlockTracker,
    orphans: RuntimeOrphanPool,
}

impl HarnessNode {
    fn new(tip: [u8; 32]) -> Self {
        Self {
            tip,
            tracker: MissingBlockTracker::new(8, 2, 4),
            orphans: RuntimeOrphanPool::new(16, 8),
        }
    }

    fn deliver_child_before_parent(&mut self, child: OrphanBlock) -> Vec<[u8; 32]> {
        assert_ne!(
            self.tip, child.parent_hash,
            "harness precondition: parent missing"
        );
        assert_eq!(
            self.orphans.insert(child.clone()),
            OrphanInsertOutcome::Inserted
        );
        self.tracker.note_orphan(
            child.block_hash,
            child.parent_hash,
            child.height.checked_sub(1),
        );
        self.tracker.next_request_batch(child.height)
    }

    fn deliver_parent(&mut self, parent_hash: [u8; 32]) -> Vec<[u8; 32]> {
        self.tip = parent_hash;
        self.tracker.resolve(&parent_hash);
        let children = self.orphans.take_children(&parent_hash);
        for child in &children {
            self.tip = child.block_hash;
        }
        children.into_iter().map(|child| child.block_hash).collect()
    }
}

#[test]
fn child_before_parent_requests_parent_then_converges_without_leak() {
    let genesis = h(0);
    let parent = h(1);
    let child = orphan(2, 1, 2);

    let mut node_a = HarnessNode::new(parent);
    let mut node_b = HarnessNode::new(genesis);
    let mut node_c = HarnessNode::new(parent);

    let requests = node_b.deliver_child_before_parent(child);
    assert_eq!(requests, vec![parent], "missing parent requested once");
    assert_eq!(node_b.tip, genesis, "child is not canonical prematurely");
    assert!(
        node_b.tracker.next_request_batch(2).is_empty(),
        "same-round duplicate delivery cannot storm requests"
    );

    let promoted = node_b.deliver_parent(parent);
    assert_eq!(promoted, vec![h(2)], "child reprocessed after parent");
    node_a.tip = h(2);
    node_c.tip = h(2);

    assert_eq!(node_a.tip, node_b.tip);
    assert_eq!(node_b.tip, node_c.tip);
    assert!(node_b.orphans.is_empty(), "no orphan leak remains");
    assert_eq!(node_b.tracker.missing_len(), 0, "no request leak remains");
}

#[test]
fn reordered_delivery_restart_policy_is_clean_and_rediscovers_orphan() {
    let genesis = h(0);
    let parent = h(1);
    let child = orphan(2, 1, 2);

    let mut before_restart = HarnessNode::new(genesis);
    assert_eq!(
        before_restart.deliver_child_before_parent(child.clone()),
        vec![parent]
    );
    assert_eq!(before_restart.orphans.len(), 1);

    let mut after_restart = HarnessNode::new(genesis);
    assert_eq!(
        after_restart.tracker.missing_len(),
        0,
        "runtime orphan request state is not persisted"
    );
    assert!(after_restart.orphans.is_empty());
    assert_eq!(
        after_restart.deliver_child_before_parent(child),
        vec![parent],
        "child redelivery after restart deterministically rediscovers parent"
    );
    assert_eq!(after_restart.deliver_parent(parent), vec![h(2)]);
    assert_eq!(after_restart.tip, h(2));
}
