package sign

type Level int

const (
	Level2 = iota
	Level3
	Level5
)

func (l Level) String() string {
	switch l {
	case Level2:
		return "ML-DSA-44"
	case Level3:
		return "ML-DSA-65"
	case Level5:
		return "ML-DSA-87"
	default:
		panic("invalid dilithium security level")
	}
}

func ToLevel(algorithm string) Level {
	switch algorithm {
	case "ML-DSA-44":
		return Level2
	case "ML-DSA-65":
		return Level3
	case "ML-DSA-87":
		return Level5
	default:
		panic("invalid dilithium signer algorithm")
	}
}
