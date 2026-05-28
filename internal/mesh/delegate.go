//go:build linux

package mesh

import (
	"fmt"
	"log/slog"

	"github.com/hashicorp/memberlist"
)

type delegate struct {
	mesh *Mesh
}

var (
	_ memberlist.Delegate      = (*delegate)(nil)
	_ memberlist.AliveDelegate = (*delegate)(nil)
	_ memberlist.EventDelegate = (*delegate)(nil)
)

func (d *delegate) NodeMeta(int) []byte           { return d.mesh.meta }
func (*delegate) NotifyMsg([]byte)                {}
func (*delegate) GetBroadcasts(int, int) [][]byte { return nil }
func (*delegate) LocalState(bool) []byte          { return nil }
func (*delegate) MergeRemoteState([]byte, bool)   {}

func (d *delegate) NotifyJoin(n *memberlist.Node)   { d.mesh.setMember(n) }
func (d *delegate) NotifyUpdate(n *memberlist.Node) { d.mesh.setMember(n) }
func (d *delegate) NotifyLeave(n *memberlist.Node)  { d.mesh.removeMember(n) }

func (d *delegate) NotifyAlive(node *memberlist.Node) error {
	policy := d.mesh.cfg.PeerPolicy
	if policy == nil {
		return nil
	}
	if node.Name == d.mesh.cfg.Self.PublicKey {
		return nil
	}
	if len(node.Meta) == 0 {
		return nil
	}
	var p Peer
	if err := decodeMeta(node.Meta, &p); err != nil {
		return err
	}
	peers := func() []Peer { return d.mesh.peerSnapshot(node.Name) }
	ok, err := policy.accept(p, peers)
	if err != nil {
		slog.Warn("peer-policy eval", "node", node.Name, "err", err)
		return err
	}
	if !ok {
		slog.Warn("peer rejected by policy", "node", node.Name)
		return fmt.Errorf("peer %s rejected by policy", node.Name)
	}
	return nil
}
