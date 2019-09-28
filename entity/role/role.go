package role

import "errors"

const (
	Admin        = "admin"
	Organization = "organization"
	Operator     = "operator"
	Owner        = "owner"
)

func Validate(r string) error {
	switch r {
	case Admin, Organization, Operator, Owner:
		return nil
	}
	return errors.New("invalid role")
}
