package postgres

import (
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/quay/claircore/toolkit/types/cpe"
	"github.com/quay/claircore/toolkit/types/cvss"
)

// TryCommonEncodePlan supports encoding directly from some domain types.
func tryCommonEncodePlan(tgt any) (plan pgtype.WrappedEncodePlanNextSetter, dst any, ok bool) {
	switch tgt := tgt.(type) {
	case *cpe.WFN:
		return &wrapCPEEncodePlan{}, (*cpeWrapper)(tgt), true
	case *cvss.V4:
		return &wrapCVSSEncodePlan[cvss.V4Metric]{}, cvssWrapper[cvss.V4Metric]{tgt}, true
	case *cvss.V3:
		return &wrapCVSSEncodePlan[cvss.V3Metric]{}, cvssWrapper[cvss.V3Metric]{tgt}, true
	case *cvss.V2:
		return &wrapCVSSEncodePlan[cvss.V2Metric]{}, cvssWrapper[cvss.V2Metric]{tgt}, true
	}
	return nil, nil, false
}

// Wrapper types for common types.
type (
	cpeWrapper                 cpe.WFN
	cvssWrapper[M cvss.Metric] struct{ cvss.Vector[M] }
)

// Implementation assertions for common types.
var (
	_ pgtype.TextValuer = (*cpeWrapper)(nil)
	_ pgtype.TextValuer = cvssWrapper[cvss.V2Metric]{}
	_ pgtype.TextValuer = cvssWrapper[cvss.V3Metric]{}
	_ pgtype.TextValuer = cvssWrapper[cvss.V4Metric]{}
)

// TextValue implements [pgtype.TextValuer].
func (c *cpeWrapper) TextValue() (txt pgtype.Text, err error) {
	if c == nil {
		return txt, nil
	}
	wfn := (*cpe.WFN)(c)
	if err := wfn.Valid(); err != nil {
		return txt, err
	}
	txt.Valid = true
	txt.String = wfn.BindFS()
	return txt, nil
}

// TextValue implements [pgtype.TextValuer].
func (c cvssWrapper[M]) TextValue() (txt pgtype.Text, err error) {
	if c.Vector == nil {
		return txt, nil
	}
	b, err := c.MarshalText()
	if err != nil {
		return txt, err
	}
	txt.Valid = true
	txt.String = string(b)
	return txt, nil
}

// [pgtype.WrappedEncodePlanNextSetter] implementations for common types:
// - [*cpe.WFN]
// - [*cvss.V4]
// - [*cvss.V3]
// - [*cvss.V2]
type (
	wrapCPEEncodePlan                 struct{ next pgtype.EncodePlan }
	wrapCVSSEncodePlan[M cvss.Metric] struct{ next pgtype.EncodePlan }
)

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapCPEEncodePlan) Encode(value any, buf []byte) ([]byte, error) {
	return w.next.Encode((*cpeWrapper)(value.(*cpe.WFN)), buf)
}

// SetNext implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapCPEEncodePlan) SetNext(next pgtype.EncodePlan) { w.next = next }

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapCVSSEncodePlan[M]) Encode(value any, buf []byte) (newBuf []byte, err error) {
	return w.next.Encode(cvssWrapper[M]{value.(cvss.Vector[M])}, buf)
}

// SetNext implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapCVSSEncodePlan[M]) SetNext(next pgtype.EncodePlan) { w.next = next }
