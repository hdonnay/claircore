package driver

import (
	"encoding"
	"fmt"
)

var (
	_ encoding.TextAppender    = ArtifactState(0)
	_ encoding.TextAppender    = Severity(0)
	_ encoding.TextUnmarshaler = (*ArtifactState)(nil)
	_ encoding.TextUnmarshaler = (*Severity)(nil)
)

func (a ArtifactState) AppendText(b []byte) ([]byte, error) {
	idx := int(a) - 0
	if a < 0 || idx >= len(_ArtifactState_index)-1 {
		return b, fmt.Errorf("undefined ArtifactState: %d", int64(a))
	}
	return append(b, _ArtifactState_name[_ArtifactState_index[idx]:_ArtifactState_index[idx+1]]...), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (a *ArtifactState) UnmarshalText(text []byte) error {
	switch in := string(text); in {
	case `unknown`:
		*a = ArtifactStateUnknown
	case `vulnerable`:
		*a = ArtifactStateVulnerable
	case `unaffected`:
		*a = ArtifactStateUnaffected
	case `end-of-life`:
		*a = ArtifactStateEndOfLife
	default:
		return fmt.Errorf("undefined ArtifactState: %q", in)
	}
	return nil
}

func (s Severity) AppendText(b []byte) ([]byte, error) {
	idx := int(s) - 0
	if s < 0 || idx >= len(_Severity_index)-1 {
		return b, fmt.Errorf("undefined Severity: %d", int64(s))
	}
	return append(b, _Severity_name[_Severity_index[idx]:_Severity_index[idx+1]]...), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (s *Severity) UnmarshalText(text []byte) error {
	switch in := string(text); in {
	case `unknown`:
		*s = SeverityUnknown
	case `negligible`:
		*s = SeverityNegligible
	case `low`:
		*s = SeverityLow
	case `medium`:
		*s = SeverityMedium
	case `high`:
		*s = SeverityHigh
	case `critical`:
		*s = SeverityCritical
	default:
		return fmt.Errorf("undefined Severity: %q", in)
	}
	return nil
}
