//go:build linux

package mesh

import "github.com/hashicorp/memberlist"

// Thin adapter forwarding memberlist callbacks into the membership engine (member.go).

type delegate struct {
	mesh *Mesh
}

var (
	_ memberlist.Delegate         = (*delegate)(nil)
	_ memberlist.EventDelegate    = (*delegate)(nil)
	_ memberlist.ConflictDelegate = (*delegate)(nil)
)

func (d *delegate) NodeMeta(int) []byte { return *d.mesh.meta.Load() }

func (*delegate) NotifyMsg([]byte) {}

func (*delegate) GetBroadcasts(int, int) [][]byte { return nil }

func (*delegate) LocalState(bool) []byte { return nil }

func (*delegate) MergeRemoteState([]byte, bool) {}

func (d *delegate) NotifyJoin(n *memberlist.Node) { d.mesh.setMember(n) }

func (d *delegate) NotifyUpdate(n *memberlist.Node) { d.mesh.setMember(n) }

func (d *delegate) NotifyLeave(n *memberlist.Node) { d.mesh.removeMember(n) }

func (d *delegate) NotifyConflict(existing, other *memberlist.Node) {
	d.mesh.handleConflict(existing, other)
}
