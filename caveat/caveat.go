package caveat

import (
	"fmt"
	"strings"

	"gopkg.in/macaroon.v2"
)

type Caveat struct {
	Condition string
	Value     string
}

func EncodeCaveat(caveat Caveat) string {
	return fmt.Sprintf("%s=%s", caveat.Condition, caveat.Value)
}

func DecodeCaveat(caveatString string) (Caveat, error) {
	splitted := strings.Split(caveatString, "=")
	if len(splitted) != 2 {
		return Caveat{}, fmt.Errorf("L402 does not have the right format: %s", caveatString)
	}
	return Caveat{Condition: splitted[0], Value: splitted[1]}, nil
}

func NewCaveat(condition string, value string) Caveat {
	return Caveat{Condition: condition, Value: value}
}

func AddFirstPartyCaveats(mac *macaroon.Macaroon, caveats []Caveat) error {
	for _, c := range caveats {
		rawCaveat := []byte(EncodeCaveat(c))
		if err := mac.AddFirstPartyCaveat(rawCaveat); err != nil {
			return err
		}
	}
	return nil
}

func VerifyCaveats(rawCaveats []string, conditions []Caveat) error {
	caveats := make([]Caveat, 0, len(rawCaveats))
	for _, rawCaveat := range rawCaveats {
		caveat, err := DecodeCaveat(rawCaveat)
		// Continue to avoid failing if contains any third party caveats
		if err != nil {
			continue
		}
		caveats = append(caveats, caveat)
	}
	if !CheckIfConditionsMatchCaveats(caveats, conditions) {
		return fmt.Errorf("Caveats don't match")
	}
	return nil
}

func CheckIfConditionsMatchCaveats(caveats []Caveat, conditions []Caveat) bool {
	// A macaroon can have more caveats (Third-party as well) than expected conditions
	// but atleast should contain caveats for required conditions
	if len(caveats) < len(conditions) {
		return false
	}
	caveatsExist := make(map[string]Caveat, len(caveats))
	for _, caveat := range caveats {
		caveatsExist[caveat.Condition] = caveat
	}
	for _, condition := range conditions {
		if _, ok := caveatsExist[condition.Condition]; !ok {
			return false
		}
		if caveatsExist[condition.Condition].Value != condition.Value {
			return false
		}
	}
	return true
}
