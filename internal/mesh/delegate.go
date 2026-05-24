package mesh

import (
	"log/slog"

	"github.com/hashicorp/memberlist"
)

type delegate struct {
	meta []byte
}

func (d *delegate) NodeMeta(int) []byte           { return d.meta }
func (*delegate) NotifyMsg([]byte)                {}
func (*delegate) GetBroadcasts(int, int) [][]byte { return nil }
func (*delegate) LocalState(bool) []byte          { return nil }
func (*delegate) MergeRemoteState([]byte, bool)   {}

func (*delegate) NotifyConflict(existing, other *memberlist.Node) {
	slog.Warn("node name conflict", "name", other.Name, "existing", existing.Address(), "other", other.Address())
}
