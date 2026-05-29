package testdata

type KeyGenerationPayload struct {
	VsID       int          `json:"vsId"`
	Algorithm  string       `json:"algorithm"`
	Mode       string       `json:"mode"`
	Revision   string       `json:"revision"`
	IsSample   bool         `json:"isSample"`
	TestGroups []TestGroups `json:"testGroups"`
}

type TestGroups struct {
	TgID         int        `json:"tgId"`
	TestType     string     `json:"testType"`
	ParameterSet string     `json:"parameterSet"`
	Tests        []KeySeeds `json:"tests"`
}

type KeySeeds struct {
	TcID int    `json:"tcId"`
	Z    string `json:"z"`
	D    string `json:"d"`
}

type ExpectedKeyGenResult struct {
	VsID       int                     `json:"vsId"`
	Algorithm  string                  `json:"algorithm"`
	Mode       string                  `json:"mode"`
	Revision   string                  `json:"revision"`
	IsSample   bool                    `json:"isSample"`
	TestGroups []ExpectedKeyGenPayload `json:"testGroups"`
}

type ExpectedKeyGenPayload struct {
	TgID  int                  `json:"tgId"`
	Tests []ExpectedKeyGenTest `json:"tests"`
}

type ExpectedKeyGenTest struct {
	TcID int    `json:"tcId"`
	Ek   string `json:"ek"`
	Dk   string `json:"dk"`
}

type EncapsDecapsPayload struct {
	VsID       int                     `json:"vsId"`
	Algorithm  string                  `json:"algorithm"`
	Mode       string                  `json:"mode"`
	Revision   string                  `json:"revision"`
	IsSample   bool                    `json:"isSample"`
	TestGroups []EncapsDecapsTestGroup `json:"testGroups"`
}

type EncapsDecapsTestGroup struct {
	TgID         int                       `json:"tgId"`
	TestType     string                    `json:"testType"`
	ParameterSet string                    `json:"parameterSet"`
	Function     string                    `json:"function"`
	Tests        []EncapsDecapsTestPayload `json:"tests"`
	Dk           string                    `json:"dk,omitempty"`
}

type EncapsDecapsTestPayload struct {
	TcID int    `json:"tcId"`
	Ek   string `json:"ek"`
	M    string `json:"m"`
	C    string `json:"c"`
}

type EncapsDecapsExpectedResults struct {
	VsID       int                              `json:"vsId"`
	Algorithm  string                           `json:"algorithm"`
	Mode       string                           `json:"mode"`
	Revision   string                           `json:"revision"`
	IsSample   bool                             `json:"isSample"`
	TestGroups []EncapsDecapsExpectedTestGroups `json:"testGroups"`
}

type EncapsDecapsExpectedTestGroups struct {
	TgID  int                         `json:"tgId"`
	Tests []EncapsDecapsExpectedTests `json:"tests"`
}

type EncapsDecapsExpectedTests struct {
	TcID int    `json:"tcId"`
	C    string `json:"c"`
	K    string `json:"k"`
}
