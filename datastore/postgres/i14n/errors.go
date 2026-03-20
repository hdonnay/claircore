package i14n

import (
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

// ErrorType returns an "error.type" attribute.
//
// See [https://www.postgresql.org/docs/18/errcodes-appendix.html].
func errorType(code string) attribute.KeyValue {
	class := code[:2]
	switch class {
	case "01":
		return errorType01
	case "02":
		return errorType02
	case "08":
		return errorType08
	case "09":
		return errorType09
	case "0A":
		return errorType0A
	case "0B":
		return errorType0B
	case "0F":
		return errorType0F
	case "0L":
		return errorType0L
	case "0P":
		return errorType0P
	case "0Z":
		return errorType0Z
	case "10":
		return errorType10
	case "20":
		return errorType20
	case "21":
		return errorType21
	case "22":
		return errorType22
	case "23":
		return errorType23
	case "24":
		return errorType24
	case "25":
		return errorType25
	case "26":
		return errorType26
	case "27":
		return errorType27
	case "28":
		return errorType28
	case "2B":
		return errorType2B
	case "2D":
		return errorType2D
	case "2F":
		return errorType2F
	case "34":
		return errorType34
	case "38":
		return errorType38
	case "39":
		return errorType39
	case "3B":
		return errorType3B
	case "3D":
		return errorType3D
	case "3F":
		return errorTypeP0
	case "40":
		return errorType40
	case "42":
		return errorType42
	case "44":
		return errorType44
	case "53":
		return errorType53
	case "54":
		return errorType54
	case "55":
		return errorType55
	case "57":
		return errorType57
	case "58":
		return errorType58
	case "F0":
		return errorTypeF0
	case "HV":
		return errorTypeHV
	case "P0":
		return errorTypeP0
	case "XX":
		return errorTypeXX
	default:
	}
	return semconv.ErrorTypeOther
}

var (
	errorType01 = semconv.ErrorTypeKey.String("Warning")
	errorType02 = semconv.ErrorTypeKey.String("No Data")
	errorType03 = semconv.ErrorTypeKey.String("SQL Statement Not Yet Complete")
	errorType08 = semconv.ErrorTypeKey.String("Connection Exception")
	errorType09 = semconv.ErrorTypeKey.String("Triggered Action Exception")
	errorType0A = semconv.ErrorTypeKey.String("Feature Not Supported")
	errorType0B = semconv.ErrorTypeKey.String("Invalid Transaction Initiation")
	errorType0F = semconv.ErrorTypeKey.String("Locator Exception")
	errorType0L = semconv.ErrorTypeKey.String("Invalid Grantor")
	errorType0P = semconv.ErrorTypeKey.String("Invalid Role Specification")
	errorType0Z = semconv.ErrorTypeKey.String("Diagnostics Exception")
	errorType10 = semconv.ErrorTypeKey.String("XQuery Error")
	errorType20 = semconv.ErrorTypeKey.String("Case Not Found")
	errorType21 = semconv.ErrorTypeKey.String("Cardinality Violation")
	errorType22 = semconv.ErrorTypeKey.String("Data Exception")
	errorType23 = semconv.ErrorTypeKey.String("Integrity Constraint Violation")
	errorType24 = semconv.ErrorTypeKey.String("Invalid Cursor State")
	errorType25 = semconv.ErrorTypeKey.String("Invalid Transaction State")
	errorType26 = semconv.ErrorTypeKey.String("Invalid SQL Statement Name")
	errorType27 = semconv.ErrorTypeKey.String("Triggered Data Change Violation")
	errorType28 = semconv.ErrorTypeKey.String("Invalid Authorization Specification")
	errorType2B = semconv.ErrorTypeKey.String("Dependent Privilege Descriptors Still Exist")
	errorType2D = semconv.ErrorTypeKey.String("Invalid Transaction Termination")
	errorType2F = semconv.ErrorTypeKey.String("SQL Routine Exception")
	errorType34 = semconv.ErrorTypeKey.String("Invalid Cursor Name")
	errorType38 = semconv.ErrorTypeKey.String("External Routine Exception")
	errorType39 = semconv.ErrorTypeKey.String("External Routine Invocation Exception")
	errorType3B = semconv.ErrorTypeKey.String("Savepoint Exception")
	errorType3D = semconv.ErrorTypeKey.String("Invalid Catalog Name")
	errorType3F = semconv.ErrorTypeKey.String("Invalid Schema Name")
	errorType40 = semconv.ErrorTypeKey.String("Transaction Rollback")
	errorType42 = semconv.ErrorTypeKey.String("Syntax Error or Access Rule Violation")
	errorType44 = semconv.ErrorTypeKey.String("WITH CHECK OPTION Violation")
	errorType53 = semconv.ErrorTypeKey.String("Insufficient Resources")
	errorType54 = semconv.ErrorTypeKey.String("Program Limit Exceeded")
	errorType55 = semconv.ErrorTypeKey.String("Object Not In Prerequisite State")
	errorType57 = semconv.ErrorTypeKey.String("Operator Intervention")
	errorType58 = semconv.ErrorTypeKey.String("System (external)")
	errorTypeF0 = semconv.ErrorTypeKey.String("Configuration File")
	errorTypeHV = semconv.ErrorTypeKey.String("Foreign Data Wrapper")
	errorTypeP0 = semconv.ErrorTypeKey.String("PL/pgSQL")
	errorTypeXX = semconv.ErrorTypeKey.String("Internal")
)
