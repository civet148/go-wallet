package wallet

import "fmt"

type OpType int

const (
	OpType_Load    OpType = 1
	OpType_Create  OpType = 2
	OpType_Recover OpType = 3
	OpType_Verify  OpType = 4
)

func (t OpType) String() string {
	switch t {
	case OpType_Load:
		return "OpType_Load"
	case OpType_Create:
		return "OpType_Create"
	case OpType_Recover:
		return "OpType_Recover"
	case OpType_Verify:
		return "OpType_Verify"
	}
	return fmt.Sprintf("OpType_Unknown")
}

func (t OpType) GoString() string {
	return t.String()
}
