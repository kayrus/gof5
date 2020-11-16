package netaddr

import (
	"bytes"
	"errors"
	"math/big"
	"net"
)

type ipTree struct {
	net             *net.IPNet
	left, right, up *ipTree
}

// setLeft helps maintain the bidirectional relationships in the tree. Always
// use it to set the left child of a node.
func (t *ipTree) setLeft(child *ipTree) {
	if t.left != nil && t == t.left.up {
		t.left.up = nil
	}
	t.left = child
	if child != nil {
		child.up = t
	}
}

// setRight helps maintain the bidirectional relationships in the tree. Always
// use it to set the right child of a node.
func (t *ipTree) setRight(child *ipTree) {
	if t.right != nil && t == t.right.up {
		t.right.up = nil
	}
	t.right = child
	if child != nil {
		child.up = t
	}
}

// trimLeft trims CIDRs that overlap top from the left child
func (t *ipTree) trimLeft(top *ipTree) *ipTree {
	if t == nil {
		return nil
	}

	if ContainsNet(top.net, t.net) {
		return t.left.trimLeft(top)
	}
	t.setRight(t.right.trimLeft(top))
	return t
}

// trimRight trims CIDRs that overlap top from the right child
func (t *ipTree) trimRight(top *ipTree) *ipTree {
	if t == nil {
		return nil
	}

	if ContainsNet(top.net, t.net) {
		return t.right.trimRight(top)
	}
	t.setLeft(t.left.trimRight(top))
	return t
}

// insert adds the given node to the tree if its CIDR is not already in the
// set. The new node's CIDR is added in the correct spot and any existing
// subsets are removed from the tree. This method does not optimize the tree by
// adding CIDRs that can be combined.
func (t *ipTree) insert(newNode *ipTree) *ipTree {
	if t == nil {
		return newNode
	}

	if ContainsNet(t.net, newNode.net) {
		return t
	}

	if ContainsNet(newNode.net, t.net) {
		// Replace the current top node and trim the tree
		newNode.setLeft(t.left.trimLeft(newNode))
		newNode.setRight(t.right.trimRight(newNode))

		// Check the left-most leaf to see if it can be combined with this one
		return newNode
	}

	if bytes.Compare(newNode.net.IP, t.net.IP) < 0 {
		t.setLeft(t.left.insert(newNode))
	} else {
		t.setRight(t.right.insert(newNode))
	}
	return t
}

// contains returns true if the given IP is in the set.
func (t *ipTree) contains(newNode *ipTree) bool {
	if t == nil || newNode == nil {
		return false
	}

	if ContainsNet(t.net, newNode.net) {
		return true
	}
	if ContainsNet(newNode.net, t.net) {
		return false
	}
	if bytes.Compare(newNode.net.IP, t.net.IP) < 0 {
		return t.left.contains(newNode)
	}
	return t.right.contains(newNode)
}

// remove takes out the node and adjusts the tree recursively
func (t *ipTree) remove() *ipTree {
	replaceMe := func(newChild *ipTree) *ipTree {
		if t.up != nil {
			if t == t.up.left {
				t.up.setLeft(newChild)
			} else {
				t.up.setRight(newChild)
			}
		} else if newChild != nil {
			newChild.up = t.up
		}
		return newChild
	}

	if t.left != nil && t.right != nil {
		next := t.next()
		t.net = next.net
		next.remove()
		return t
	}
	if t.left != nil {
		return replaceMe(t.left)
	}
	if t.right != nil {
		return replaceMe(t.right)
	}
	return replaceMe(nil)
}

// removeNet removes all of the IPs in the given net from the set
func (t *ipTree) removeNet(net *net.IPNet) (top *ipTree) {
	if t == nil {
		return
	}
	// If net starts before me.net, recursively remove net from the left
	if bytes.Compare(net.IP, t.net.IP) < 0 {
		t.left = t.left.removeNet(net)
	}

	// If any CIDRs in `net - me.net` come after me.net, remove net from
	// the right
	diff := netDifference(net, t.net)
	for _, n := range diff {
		if bytes.Compare(t.net.IP, n.IP) < 0 {
			t.right = t.right.removeNet(net)
			break
		}
	}

	top = t
	if ContainsNet(net, t.net) {
		// Remove the current node
		top = t.remove()
	} else if ContainsNet(t.net, net) {
		diff = netDifference(t.net, net)
		t.net = diff[0]
		for _, n := range diff[1:] {
			top = top.insert(&ipTree{net: n})
		}
	}
	return
}

// first returns the first node in the tree or nil if there are none. It is
// always the left-most node.
func (t *ipTree) first() *ipTree {
	if t == nil {
		return nil
	}
	if t.left == nil {
		return t
	}
	return t.left.first()
}

// next returns the node following the given one in order or nil if it is the last.
func (t *ipTree) next() *ipTree {
	if t.right != nil {
		next := t.right
		for next.left != nil {
			next = next.left
		}
		return next
	}

	next := t
	for next.up != nil {
		if next.up.left == next {
			return next.up
		}
		next = next.up
	}
	return nil
}

// prev returns the node preceding the given one in order or nil if it is the first.
func (t *ipTree) prev() *ipTree {
	if t.left != nil {
		prev := t.left
		for prev.right != nil {
			prev = prev.right
		}
		return prev
	}

	prev := t
	for prev.up != nil {
		if prev.up.right == prev {
			return prev.up
		}
		prev = prev.up
	}
	return nil
}

// walk visits all of the nodes in order by passing each node, in turn, to the
// given visit function.
func (t *ipTree) walk(visit func(*ipTree)) {
	if t == nil {
		return
	}
	t.left.walk(visit)
	visit(t)
	t.right.walk(visit)
}

// size returns the number of IPs in the set.
// It isn't efficient and only meant for testing.
func (t *ipTree) size() *big.Int {
	s := big.NewInt(0)
	if t != nil {
		ones, bits := t.net.Mask.Size()
		s.Lsh(big.NewInt(1), uint(bits-ones))
		s.Add(s, t.left.size())
		s.Add(s, t.right.size())
	}
	return s
}

// height returns the length of the maximum path from top node to leaf
// It isn't efficient and only meant for testing.
func (t *ipTree) height() uint {
	if t == nil {
		return 0
	}

	s := t.left.height()
	if s < t.right.height() {
		s = t.right.height()
	}
	return s + 1
}

// numNodes Return the number of nodes in the underlying tree It isn't
// efficient and only meant for testing.
func (t *ipTree) numNodes() int {
	if t == nil {
		return 0
	}
	return 1 + t.left.numNodes() + t.right.numNodes()
}

func (t *ipTree) validate() []error {
	errs := []error{}

	// if tree is nil, then it is valid
	if t == nil {
		return errs
	}

	// assert root's up is nil
	if t.up != nil {
		errs = append(errs, errors.New("root up must be nil"))
	}

	// validate each node
	var lastNode *ipTree
	t.walk(func(n *ipTree) {
		// assert that the node's are linked properly
		if n.left != nil && n.left.up != n {
			errs = append(errs, errors.New("linkage error: left.up node must equal node"))
		}
		if n.right != nil && n.right.up != n {
			errs = append(errs, errors.New("linkage error: right.up node must equal node"))
		}

		if n.net == nil {
			errs = append(errs, errors.New("each node in tree must have a network"))
		} else if !n.net.IP.Mask(n.net.Mask).Equal(n.net.IP) {
			// verify that the network is valid
			errs = append(errs, errors.New("cidr invalid: "+n.net.String()))
		}

		// assert order is correct
		if lastNode != nil && bytes.Compare(lastNode.net.IP, n.net.IP) >= 0 {
			errs = append(errs, errors.New("nodes must be in order: "+lastNode.net.IP.String()+" !< "+n.net.IP.String()))
		}
		lastNode = n
	})

	return errs
}
