//go:build linux

package mesh

import "github.com/hashicorp/memberlist"

type delegate struct {
	mesh *Mesh
}

var (
	_ memberlist.Delegate         = (*delegate)(nil)
	_ memberlist.EventDelegate    = (*delegate)(nil)
	_ memberlist.ConflictDelegate = (*delegate)(nil)
)

func (d *delegate) NodeMeta(int) []byte { return *d.mesh.meta.Load() }

func (d *delegate) NotifyMsg(buf []byte) { d.mesh.handleRevocationMsg(buf) }

func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte {
	if d.mesh.revocationBroadcasts == nil {
		return nil
	}
	return d.mesh.revocationBroadcasts.GetBroadcasts(overhead, limit)
}

func (d *delegate) LocalState(bool) []byte { return d.mesh.revocationState() }

func (d *delegate) MergeRemoteState(buf []byte, _ bool) { d.mesh.mergeRevocationState(buf) }

func (d *delegate) NotifyJoin(n *memberlist.Node) { d.mesh.setMember(n) }

func (d *delegate) NotifyUpdate(n *memberlist.Node) { d.mesh.setMember(n) }

func (d *delegate) NotifyLeave(n *memberlist.Node) { d.mesh.removeMember(n) }

func (d *delegate) NotifyConflict(existing, other *memberlist.Node) {
	d.mesh.handleConflict(existing, other)
}
