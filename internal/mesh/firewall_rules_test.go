//go:build linux

package mesh

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shoenig/test/must"
)

func TestParseFirewallRules(t *testing.T) {
	p, err := ParseFirewallRules("")
	must.NoError(t, err)
	must.Nil(t, p, must.Sprint("empty rules compile to nil"))

	_, err = ParseFirewallRules("allow(")
	must.Error(t, err, must.Sprint("a malformed expr fails to compile"))

	_, err = ParseFirewallRules(`peer.bogus == 1`)
	must.Error(t, err, must.Sprint("an unknown field is caught by the typed env"))

	_, err = ParseFirewallRules(`[allow("sctp", 22)]`)
	must.ErrorContains(t, err, "proto", must.Sprint("an unsupported proto is rejected at parse"))

	_, err = ParseFirewallRules(`[allow("tcp", 99999)]`)
	must.ErrorContains(t, err, "out of", must.Sprint("an out-of-range port is rejected at parse"))

	_, err = ParseFirewallRules(`[allow("tcp", 22, peer.tags["role"] == "db")]`)
	must.NoError(t, err, must.Sprint("a well-formed rule compiles"))
}

func TestParseFirewallRulesFlag_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fw.rules")
	must.NoError(t, os.WriteFile(path, []byte("  [allow(\"tcp\", 22)]\n"), 0o600))

	p, err := ParseFirewallRulesFlag("@" + path)
	must.NoError(t, err)
	must.NotNil(t, p, must.Sprint("@file is read, trimmed, and compiled"))

	_, err = ParseFirewallRulesFlag("@" + filepath.Join(dir, "missing"))
	must.Error(t, err, must.Sprint("a missing @file errors"))
}

func dbPeer() fwPeer {
	return fwPeer{Key: "k1", Address: "fdcc::a1", Tags: map[string]string{"role": "db-client"}}
}
func webPeer() fwPeer {
	return fwPeer{Key: "k2", Address: "fdcc::b2", Tags: map[string]string{"role": "web"}}
}

func compile(t *testing.T, spec string, peer fwPeer) peerRules {
	t.Helper()
	fp, err := ParseFirewallRules(spec)
	must.NoError(t, err)
	r, err := fp.compilePeer(peer)
	must.NoError(t, err)
	return r
}

func TestCompilePeer_TagGated(t *testing.T) {
	spec := `[allow("tcp", 5432, peer.tags["role"] == "db-client"), allow("tcp", [22, 179])]`

	db := compile(t, spec, dbPeer())
	must.Eq(t, []portRange{{22, 22}, {179, 179}, {5432, 5432}}, db.tcp, must.Sprint("db peer gets 22,179,5432"))
	must.SliceEmpty(t, db.udp, must.Sprint("no udp rule allowed, so no udp ports"))

	web := compile(t, spec, webPeer())
	must.Eq(t, []portRange{{22, 22}, {179, 179}}, web.tcp, must.Sprint("non-db peer only gets 22,179"))
}

func TestCompilePeer_ProtoAndForms(t *testing.T) {
	udp := compile(t, `[allow("udp", 53)]`, dbPeer())
	must.Eq(t, []portRange{{53, 53}}, udp.udp)
	must.SliceEmpty(t, udp.tcp, must.Sprint("a udp rule yields no tcp ports"))

	// int, list, and "lo-hi" range forms.
	r := compile(t, `[allow("tcp", 80), allow("tcp", [443, 8443]), allow("tcp", "9000-9100")]`, dbPeer())
	must.Eq(t, []portRange{{80, 80}, {443, 443}, {8443, 8443}, {9000, 9100}}, r.tcp)
}

func TestCompilePeer_MergeAndAll(t *testing.T) {
	// overlapping/adjacent spans coalesce.
	m := compile(t, `[allow("tcp", "80-90"), allow("tcp", "85-100"), allow("tcp", 101)]`, dbPeer())
	must.Eq(t, []portRange{{80, 101}}, m.tcp, must.Sprint("overlapping and adjacent spans merge"))

	all := compile(t, `[allow("tcp", "0-65535")]`, dbPeer())
	must.Eq(t, []portRange{{0, maxPort}}, all.tcp)

	none := compile(t, `[allow("tcp", 22, peer.tags["role"] == "db-client")]`, webPeer())
	must.True(t, none.empty(), must.Sprint("a peer the condition rejects gets nothing"))
}
