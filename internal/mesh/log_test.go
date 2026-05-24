package mesh

import (
	"context"
	"log/slog"
	"testing"

	"github.com/shoenig/test/must"
)

type captureHandler struct {
	records []slog.Record
}

func (*captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func TestMemberlistLogWriter(t *testing.T) {
	for _, tc := range []struct {
		in    string
		level slog.Level
		text  string
	}{
		{"[ERR] memberlist boom\n", slog.LevelError, "memberlist boom"},
		{"[ERROR] memberlist boom\n", slog.LevelError, "memberlist boom"},
		{"[WARN] something\n", slog.LevelWarn, "something"},
		{"[INFO] heartbeat\n", slog.LevelInfo, "heartbeat"},
		{"[DEBUG] verbose\n", slog.LevelDebug, "verbose"},
		{"unknown line\n", slog.LevelInfo, "unknown line"},
	} {
		prev := slog.Default()
		ch := &captureHandler{}
		slog.SetDefault(slog.New(ch))

		n, err := memberlistLogWriter{}.Write([]byte(tc.in))
		slog.SetDefault(prev)

		must.NoError(t, err, must.Sprintf("input=%q", tc.in))
		must.EqOp(t, len(tc.in), n)
		must.SliceLen(t, 1, ch.records, must.Sprintf("input=%q", tc.in))
		must.EqOp(t, tc.level, ch.records[0].Level)
		must.EqOp(t, tc.text, ch.records[0].Message)
	}
}
