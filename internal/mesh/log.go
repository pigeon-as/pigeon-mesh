package mesh

import (
	"context"
	"log"
	"log/slog"
	"strings"
)

var memberlistLogLevels = []struct {
	prefix string
	level  slog.Level
}{
	{"[ERR] ", slog.LevelError},
	{"[ERROR] ", slog.LevelError},
	{"[WARN] ", slog.LevelWarn},
	{"[INFO] ", slog.LevelInfo},
	{"[DEBUG] ", slog.LevelDebug},
}

type memberlistLogWriter struct{}

func (memberlistLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	level := slog.LevelInfo
	for _, t := range memberlistLogLevels {
		if rest, ok := strings.CutPrefix(line, t.prefix); ok {
			level, line = t.level, rest
			break
		}
	}
	slog.Default().Log(context.Background(), level, line)
	return len(p), nil
}

func newMemberlistLogger() *log.Logger {
	return log.New(memberlistLogWriter{}, "", 0)
}
