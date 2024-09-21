package testutil

type Address struct {
	Street string `sensitive:"data"`
}

type Profile struct {
	UserID   string  `sensitive:"subjectID"`
	Fullname string  `sensitive:"data,replace=deleted pii"`
	Gender   string  `sensitive:"data"`
	Address  Address `sensitive:"dive"`
	Country  string
}

func (p Profile) TEST_PII_SubjectID() string {
	return p.UserID
}

func (p Profile) TEST_PII_Replacement(piiField string) string {
	switch piiField {
	case "Fullname":
		return "deleted pii"
	}

	return ""
}

type InvalidStruct1 struct {
	Val1 string
	Val2 string `sensitive:"data"`
}

type InvalidStruct2 struct {
	Val1 string `sensitive:"subjectID"`
	Val2 string `sensitive:"subjectID"`
}

type InvalidStruct3 struct {
	Val1 interface{} `sensitive:"subjectID"`
	Val2 int         `sensitive:"data"`
}

type IgnoredStruct struct {
	Val string
}
