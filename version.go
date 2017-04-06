package apksign

type SigningVersion int

const (
	APKSignUnknown SigningVersion = iota
	APKSignV1
	APKSignV2
)

func (sv SigningVersion) String() string {
	switch sv {
	case APKSignV1:
		return "1"
	case APKSignV2:
		return "2"
	default:
		return ""
	}
}
