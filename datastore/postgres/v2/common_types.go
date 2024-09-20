package postgres

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/quay/claircore/toolkit/types"
	"github.com/quay/claircore/toolkit/types/cpe"
	"github.com/quay/claircore/toolkit/types/cvss"
)

// TryCommonEncodePlan supports encoding directly from some common types.
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
	case error:
		return &wrapErrorEncodePlan{}, encodeErrorWrapper{tgt}, true
	}
	return nil, nil, false
}

// TryCommonScanPlan supports scanning directly into some common types.
func tryCommonScanPlan(tgt any) (plan pgtype.WrappedScanPlanNextSetter, dst any, ok bool) {
	switch tgt := tgt.(type) {
	case *error:
		return &wrapErrorScanPlan{}, scanErrorWrapper{tgt}, true
	case *types.Severity:
		return &wrapSeverityScanPlan{}, (*severityWrapper)(tgt), true
	case *types.PackageKind:
		return &wrapPackageKindScanPlan{}, (*packageKindWrapper)(tgt), true
	}
	return nil, nil, false
}

// [pgtype.WrappedEncodePlanNextSetter] implementations for common types:
// - [*cpe.WFN]
// - [*cvss.V4]
// - [*cvss.V3]
// - [*cvss.V2]
type (
	wrapCPEEncodePlan                 struct{ next pgtype.EncodePlan }
	wrapCVSSEncodePlan[M cvss.Metric] struct{ next pgtype.EncodePlan }
	wrapErrorEncodePlan               struct{ next pgtype.EncodePlan }
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

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapErrorEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	return w.next.Encode(encodeErrorWrapper{value.(error)}, buf)
}

// SetNext implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapErrorEncodePlan) SetNext(next pgtype.EncodePlan) {
	w.next = next
}

var (
	_ pgtype.TextValuer = (*cpeWrapper)(nil)
	_ pgtype.TextValuer = cvssWrapper[cvss.V2Metric]{}
	_ pgtype.TextValuer = cvssWrapper[cvss.V3Metric]{}
	_ pgtype.TextValuer = cvssWrapper[cvss.V4Metric]{}
	_ pgtype.TextValuer = encodeErrorWrapper{}
)

type (
	cpeWrapper                 cpe.WFN
	cvssWrapper[M cvss.Metric] struct{ cvss.Vector[M] }
	encodeErrorWrapper         struct{ Err error }
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

// TextValue implements [pgtype.TextValuer].
func (e encodeErrorWrapper) TextValue() (txt pgtype.Text, _ error) {
	if e.Err != nil {
		txt.Valid = true
		txt.String = e.Err.Error()
	}
	return txt, nil
}

// [pgtype.WrappedScanPlanNextSetter] implementations for common types:
// - [error]
// - [*types.Severity]
// - [*types.PackageKind]
type (
	wrapErrorScanPlan       struct{ next pgtype.ScanPlan }
	wrapPackageKindScanPlan struct{ next pgtype.ScanPlan }
	wrapSeverityScanPlan    struct{ next pgtype.ScanPlan }
)

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapErrorScanPlan) Scan(src []byte, tgt any) error {
	return w.next.Scan(src, scanErrorWrapper{tgt.(*error)})
}

// SetNext implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapErrorScanPlan) SetNext(next pgtype.ScanPlan) { w.next = next }

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapPackageKindScanPlan) Scan(src []byte, dst any) error {
	return w.next.Scan(src, (*packageKindWrapper)(dst.(*types.PackageKind)))
}

// SetNext implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapPackageKindScanPlan) SetNext(next pgtype.ScanPlan) { w.next = next }

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapSeverityScanPlan) Scan(src []byte, dst any) error {
	return w.next.Scan(src, (*severityWrapper)(dst.(*types.Severity)))
}

// SetNext implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapSeverityScanPlan) SetNext(next pgtype.ScanPlan) { w.next = next }

var (
	_ pgtype.TextScanner = scanErrorWrapper{}
	_ pgtype.TextScanner = (*packageKindWrapper)(nil)
	_ pgtype.TextScanner = (*severityWrapper)(nil)
)

type (
	scanErrorWrapper   struct{ Err *error }
	packageKindWrapper types.PackageKind
	severityWrapper    types.Severity
)

// ScanText implements [pgtype.TextScanner].
func (e scanErrorWrapper) ScanText(v pgtype.Text) error {
	if v.Valid {
		*e.Err = errors.New(v.String)
	}
	return nil
}

// ScanText implements [pgtype.TextScanner].
func (p *packageKindWrapper) ScanText(v pgtype.Text) error {
	if !v.Valid {
		return errors.New("unable to scan null PackageKind")
	}
	switch v.String {
	case "source":
		*(*types.PackageKind)(p) = types.SourcePackage
	case "binary":
		*(*types.PackageKind)(p) = types.BinaryPackage
	default:
		*(*types.PackageKind)(p) = types.UnknownPackage
	}
	return nil
}

// ScanText implements [pgtype.TextScanner].
func (s *severityWrapper) ScanText(v pgtype.Text) error {
	if !v.Valid {
		return errors.New("unable to scan null Severity")
	}
	switch v.String {
	case "Unknown":
		*(*types.Severity)(s) = types.Unknown
	case "Negligible":
		*(*types.Severity)(s) = types.Negligible
	case "Low":
		*(*types.Severity)(s) = types.Low
	case "Medium":
		*(*types.Severity)(s) = types.Medium
	case "High":
		*(*types.Severity)(s) = types.High
	case "Critical":
		*(*types.Severity)(s) = types.Critical
	default:
		return fmt.Errorf("unknown Severity %q", v.String)
	}
	return nil
}
