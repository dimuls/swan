package entity

import "time"

type PasswordCode struct {
	Role      string    `db:"role"`
	Login     string    `db:"login"`
	Code      string    `db:"code"`
	CreatedAt time.Time `db:"created_at"`
}

type Admin struct {
	ID           int    `db:"id" json:"id"`
	Email        string `db:"email" json:"email"`
	PasswordHash []byte `db:"password_hash" json:"-"`
}

type Category struct {
	ID   int    `db:"id" json:"id"`
	Name string `db:"name" json:"name"`
}

func (c Category) Validate() error {
	// TODO: validate category
	return nil
}

type CategorySample struct {
	CategoryID int    `db:"category_id" json:"category_id"`
	Text       string `db:"text" json:"text"`
}

func (cs CategorySample) Validate() error {
	// TODO: validate category sample
	return nil
}

type Organization struct {
	ID           int    `db:"id" json:"id"`
	Name         string `db:"name" json:"name"`
	Email        string `db:"email" json:"email"`
	FlatsCount   int    `db:"flats_count" json:"flats_count"`
	PasswordHash []byte `db:"password_hash" json:"-"`
}

func (o Organization) Validate() error {
	// TODO: validate organization
	return nil
}

type Operator struct {
	ID                    int      `db:"id" json:"id"`
	OrganizationID        int      `db:"organization_id" json:"organization_id"`
	Phone                 string   `db:"phone" json:"phone"`
	PasswordHash          []byte   `db:"password_hash" json:"-"`
	Name                  string   `db:"name" json:"name"`
	ResponsibleCategories []string `db:"responsible_categories" json:"responsible_categories"`
}

func (o Operator) Validate() error {
	// TODO: validate operator
	return nil
}

type Owner struct {
	ID             int    `db:"id" json:"id"`
	OrganizationID int    `db:"organization_id" json:"organization_id"`
	Phone          string `db:"phone" json:"phone"`
	PasswordHash   []byte `db:"password_hash" json:"-"`
	Name           string `db:"name" json:"name"`
	Address        string `db:"address" json:"address"`
}

func (u Owner) Validate() error {
	// TODO: validate user
	return nil
}

type Request struct {
	ID             int       `db:"id" json:"id"`
	OrganizationID int       `db:"organization_id" json:"organization_id"`
	OwnerID        int       `db:"owner_id" json:"owner_id"`
	OperatorID     *int      `db:"operator_id" json:"operator_id"`
	CategoryID     *int      `db:"category_id" json:"category_id"`
	Text           string    `db:"text" json:"text"`
	Response       *string   `db:"response" json:"response"`
	Status         string    `db:"status" json:"status"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
}

func (r Request) Validate() error {
	// TODO: validate request
	return nil
}
