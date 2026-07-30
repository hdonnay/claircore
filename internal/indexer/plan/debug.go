package plan

import (
	"bufio"
	"context"
	"errors"
	"io"

	"buf.build/go/protovalidate"

	"github.com/quay/claircore/internal/proto/delim"
	"github.com/quay/claircore/internal/proto/gen/plan"
	planv1 "github.com/quay/claircore/internal/proto/gen/plan/v1"
)

type Record struct {
	Name   []string
	Expr   string
	Result []planv1.Entry
}

func LoadPlanRecord(ctx context.Context, r io.Reader) (*Record, error) {
	br := bufio.NewReaderSize(r, delim.MaxMessageSize)
	h := new(plan.Header)
	if err := delim.UnmarshalFrom(br, h); err != nil {
		return nil, err
	}
	// This package doesn't need to load the bundled descriptors, but other
	// consumers probably should.
	if err := protovalidate.Validate(h); err != nil {
		return nil, err
	}
	switch h.GetVersion() {
	case plan.Version_VERSION_V1:
		return loadPlanRecordV1(ctx, br)
	default:
		panic("unreachable")
	}
}

func loadPlanRecordV1(_ context.Context, r *bufio.Reader) (*Record, error) {
	s := new(planv1.Selectors)
	if err := delim.UnmarshalFrom(r, s); err != nil {
		return nil, err
	}
	if err := protovalidate.Validate(s); err != nil {
		return nil, err
	}

	rec := Record{
		Name: s.GetName(),
		Expr: s.GetExpression(),
	}
Read:
	for {
		i := len(rec.Result)
		rec.Result = append(rec.Result, planv1.Entry{})
		e := &rec.Result[i]

		err := delim.UnmarshalFrom(r, e)
		switch {
		case err == nil:
		case errors.Is(err, io.EOF):
			rec.Result = rec.Result[:i]
			break Read
		default:
			return nil, err
		}

		if err := protovalidate.Validate(e); err != nil {
			return nil, err
		}
	}

	return &rec, nil
}
