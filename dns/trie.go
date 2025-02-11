package dns

import (
	"strings"

	"github.com/sirupsen/logrus"
)

type TrieTree struct {
	root *Node
}

const (
	// 支持通配符（递归继承到子域名）
	FLAG_SUB_EXTENSIVE byte = 0x1
)

type Node struct {
	flags   byte
	key     string
	val     string
	child   *Node
	brother *Node
}

func (self *Node) QueryChild(key string) *Node {
	logrus.Debugf("node[%v].queryChild[%v]\n", self.key, key)
	child := self.child
	fuzzy := (*Node)(nil)
	for child != nil && child.key != key {
		if child.key == "*" {
			fuzzy = child
		}
		child = child.brother
	}

	if child != nil {
		return child
	}

	if fuzzy != nil {
		return fuzzy
	}

	return nil
}

func (self *Node) AddChild(key, val string) *Node {
	flags := self.flags

	node := &Node{flags: flags, key: key, val: val, child: nil, brother: nil}
	node.brother = self.child
	self.child = node

	return node
}

func (self *Node) DelChild(key string) {
	child := self.child
	if child == nil {
		return
	}

	if child.key == key {
		self.child = child.brother
	}

	brother := child.brother
	for brother != nil {
		if brother.key == key {
			child.brother = brother.brother
			return
		}
		child = brother
		brother = brother.brother
	}
}

func (self *TrieTree) QueryNode(key string) (*Node, *Node) {
	node := self.root
	subs := strings.Split(strings.Trim(key, "."), ".")
	fuzzy := (*Node)(nil)
	snode := (*Node)(nil)
	for i := len(subs) - 1; i >= 0; i-- {
		snode = node.QueryChild(subs[i])
		if snode == nil {
			if node.flags&FLAG_SUB_EXTENSIVE == FLAG_SUB_EXTENSIVE {
				fuzzy = node
				return nil, fuzzy
			}

			return nil, nil
		}
		logrus.Debugf("node[%v], subs[%v], snode: %v/%v\n", node.key, subs[i], snode.key, snode.val)

		node = snode
	}

	return node, node
}

func (self *TrieTree) AddNode(key, val string) {
	tKey := strings.Trim(key, ".")
	subs := strings.Split(tKey, ".")

	node := self.root
	snode := (*Node)(nil)
	for i := len(subs) - 1; i >= 0; i-- {
		if subs[i] == "*" {
			node.flags |= FLAG_SUB_EXTENSIVE
			continue
		}

		snode = node.QueryChild(subs[i])
		//if snode == nil && (node.flags&FLAG_SUB_EXTENSIVE == FLAG_SUB_EXTENSIVE) {
		if snode == nil {
			snode = node.AddChild(subs[i], "")
		}

		node = snode
	}
	node.val = val
}

func (self *TrieTree) DelNode(key string) {
	idx := strings.Index(key, ".")
	prefix := key[:idx]
	subfix := key[idx+1:]

	if prefix == "*" {
		idx = strings.Index(subfix, ".")
		prefix = subfix[:idx]
		subfix = subfix[idx+1:]
	}

	matched, _ := self.QueryNode(subfix)
	if matched != nil {
		matched.DelChild(prefix)
		return
	}

	return
}

func NewTrieTree() *TrieTree {
	return &TrieTree{root: &Node{child: nil, brother: nil, key: ".", flags: 0}}
}
