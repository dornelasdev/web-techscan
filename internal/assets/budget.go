package assets

import "errors"

// Budget is a value copy of a supported collection profile. These bounds cover
// payload reads, not memory usage, HTTP framing, or a detection CPU deadline.
type Budget struct {
	Profile              string
	MaxAssetDecodedBytes int64
	MaxAssetEncodedBytes int64
	MaxTotalDecodedBytes int64
	MaxTotalEncodedBytes int64
}

func standardBudget() Budget {
	return Budget{"standard", MaxAssetDecodedBytes, MaxAssetEncodedBytes, MaxTotalDecodedBytes, MaxTotalEncodedBytes}
}

// BudgetForProfile accepts exact profile names only. No arbitrary/unbounded
// limits or automatic fallback to another profile are supported.
func BudgetForProfile(profile string) (Budget, error) {
	switch profile {
	case "standard":
		return standardBudget(), nil
	case "expanded":
		return Budget{"expanded", 4 << 20, 8 << 20, 8 << 20, 16 << 20}, nil
	default:
		return Budget{}, errors.New("asset-budget must be standard or expanded")
	}
}

func (b Budget) validate() error {
	want, err := BudgetForProfile(b.Profile)
	if err != nil || b != want {
		return errors.New("invalid asset budget profile or limits")
	}
	return nil
}
