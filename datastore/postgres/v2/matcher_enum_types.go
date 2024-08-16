package postgres

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/quay/claircore/toolkit/types"

	"github.com/quay/claircore/updater/driver/v2"
)

// TryEnumScanPlan supports scanning directly into our enum types.
func tryEnumScanPlan(tgt any) (plan pgtype.WrappedScanPlanNextSetter, dst any, ok bool) {
	switch tgt := tgt.(type) {
	case *types.Severity:
		return &wrapSeverityScanPlan{}, (*severityWrapper)(tgt), true
	case *types.PackageKind:
		return &wrapPackageKindScanPlan{}, (*packageKindWrapper)(tgt), true
	case *driver.Architecture:
		return &wrapArchitectureScanPlan{}, (*architectureWrapper)(tgt), true
	}
	return nil, nil, false
}

// Implementation assertions for enum types.
var (
	_ pgtype.TextScanner = (*severityWrapper)(nil)
	_ pgtype.TextScanner = (*packageKindWrapper)(nil)
	_ pgtype.TextScanner = (*architectureWrapper)(nil)
)

// Wrapper types for enum types.
type (
	severityWrapper     types.Severity
	packageKindWrapper  types.PackageKind
	architectureWrapper driver.Architecture
)

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
func (a *architectureWrapper) ScanText(v pgtype.Text) error {
	if !v.Valid {
		return errors.New("unable to scan null Architecture")
	}
	switch v.String {
	case "any":
		*(*driver.Architecture)(a) = driver.ArchAny
	case "386":
		*(*driver.Architecture)(a) = driver.Arch386
	case "amd64":
		*(*driver.Architecture)(a) = driver.ArchAMD64
	case "arm":
		*(*driver.Architecture)(a) = driver.ArchArm
	case "arm64":
		*(*driver.Architecture)(a) = driver.ArchArm64
	case "mips":
		*(*driver.Architecture)(a) = driver.ArchMips
	case "mipsle":
		*(*driver.Architecture)(a) = driver.ArchMipsLE
	case "mips64":
		*(*driver.Architecture)(a) = driver.ArchMips64
	case "mips64le":
		*(*driver.Architecture)(a) = driver.ArchMips64LE
	case "ppc64":
		*(*driver.Architecture)(a) = driver.ArchPPC64
	case "ppc64le":
		*(*driver.Architecture)(a) = driver.ArchPPC64LE
	case "riscv64":
		*(*driver.Architecture)(a) = driver.ArchRiscV64
	case "s390x":
		*(*driver.Architecture)(a) = driver.ArchS390X
	default:
		return fmt.Errorf("unknown Architecture %q", v.String)
	}
	return nil
}

// [pgtype.WrappedScanPlanNextSetter] implementations for enum types:
// - [*types.Severity]
// - [*types.PackageKind]
// - [*driver.Architecture]
//
// For enum types, only the "Scan" path is implemented.
// The "Encode" path uses the builtin pgx [fmt.Stringer] adapter.
type (
	wrapSeverityScanPlan     struct{ next pgtype.ScanPlan }
	wrapPackageKindScanPlan  struct{ next pgtype.ScanPlan }
	wrapArchitectureScanPlan struct{ next pgtype.ScanPlan }
)

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapSeverityScanPlan) Scan(src []byte, dst any) error {
	return w.next.Scan(src, (*severityWrapper)(dst.(*types.Severity)))
}

// SetNext implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapSeverityScanPlan) SetNext(next pgtype.ScanPlan) { w.next = next }

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapPackageKindScanPlan) Scan(src []byte, dst any) error {
	return w.next.Scan(src, (*packageKindWrapper)(dst.(*types.PackageKind)))
}

// SetNext implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapPackageKindScanPlan) SetNext(next pgtype.ScanPlan) { w.next = next }

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapArchitectureScanPlan) Scan(src []byte, dst any) error {
	return w.next.Scan(src, (*architectureWrapper)(dst.(*driver.Architecture)))
}

// SetNext implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapArchitectureScanPlan) SetNext(next pgtype.ScanPlan) { w.next = next }
