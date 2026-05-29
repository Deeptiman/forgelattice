package kem

// Level represents a Kyber security level.
//
// Each level corresponds to a distinct security target and parameter set:
//
//   - Level512:  ~128-bit security
//   - Level768:  ~192-bit security
//   - Level1024: ~256-bit security
type Level int

const (
	Level512  Level = iota // Kyber-512
	Level768               // Kyber-768
	Level1024              // Kyber-1024
)

// String returns the canonical Kyber scheme name for the level.
func (l Level) String() string {
	switch l {
	case Level512:
		return "Kyber-512"
	case Level768:
		return "Kyber-768"
	case Level1024:
		return "Kyber-1024"
	default:
		panic("invalid kyber level")
	}
}

// ToLevel maps a ML-KEM scheme identifier to its underlying Kyber level.
func ToLevel(algorithm string) Level {
	switch algorithm {
	case "ML-KEM-512", "Kyber-512":
		return Level512
	case "ML-KEM-768", "Kyber-768":
		return Level768
	case "ML-KEM-1024", "Kyber-1024":
		return Level1024
	default:
		panic("invalid kyber level")
	}
}
