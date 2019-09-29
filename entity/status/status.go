package status

import "errors"

const (
	New        = "new"
	InProgress = "in_progress"
	Resolved   = "resolved"
	Rejected   = "rejected"
	Irrelevant = "irrelevant"
)

func Final(status string) bool {
	switch status {
	case Resolved, Rejected, Irrelevant:
		return true
	}
	return false
}

func Validate(status string) error {
	switch status {
	case New, InProgress, Resolved, Rejected, Irrelevant:
		return nil
	}
	return errors.New("invalid status")
}
