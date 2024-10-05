package privacy

import (
	"testing"
	"time"
)

type FuncCalls map[string][]time.Time

func NewFuncCalls() FuncCalls {
	return make(FuncCalls)
}

func (calls FuncCalls) AssertCount(t *testing.T, fn string, min int) {
	fnCalls, ok := calls[fn]
	if !ok {
		t.Fatalf("%s calls not found", fn)
	}
	if got := len(fnCalls); got < min {
		t.Fatalf("expect %s called at least %d, got: %d", fn, min, got)
	}
}

type Address struct {
	Street string `pii:"data"`
}

type Profile struct {
	UserID   string  `pii:"subjectID"`
	Fullname string  `pii:"data,replace=deleted pii"`
	Gender   string  `pii:"data"`
	Address  Address `pii:"dive"`
	Country  string
}

type StructSubjectNotFound struct {
	Val1 string
	Val2 string `pii:"data"`
}

type StructMultipleSubjects struct {
	Val1 string `pii:"subjectID"`
	Val2 string `pii:"subjectID"`
}

type StructSubjectInvalidType struct {
	Val1 interface{} `pii:"subjectID"`
	Val2 int         `pii:"data"`
}

type StructNotPII struct {
	Val string
}
