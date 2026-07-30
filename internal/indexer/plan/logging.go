package plan

import (
	"fmt"
	"log/slog"
	"slices"

	"github.com/google/cel-go/cel"
)

var _ slog.LogValuer = logSels(nil)

type logSels map[string]string

// LogValue implements [slog.LogValuer].
func (l logSels) LogValue() slog.Value {
	seq := func(yield func(slog.Attr) bool) {
		for k, v := range map[string]string(l) {
			if !yield(slog.String(k, v)) {
				return
			}
		}
	}
	return slog.GroupValue(slices.Collect(seq)...)
}

var _ slog.LogValuer = (*logAst)(nil)

type logAst cel.Ast

// LogValue implements [slog.LogValuer].
func (l *logAst) LogValue() slog.Value {
	s, err := cel.AstToString((*cel.Ast)(l))
	if err != nil {
		return slog.StringValue(fmt.Sprintf("ERROR: %v", err))
	}
	return slog.StringValue(s)
}
