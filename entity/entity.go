package entity

import (
	"time"

	"github.com/dimuls/swan/entity/status"
)

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
	ID   int    `db:"id" json:"id" form:"id"`
	Name string `db:"name" json:"name" form:"name"`
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
	ID           int    `db:"id" json:"id" form:"id"`
	Name         string `db:"name" json:"name" form:"name"`
	Email        string `db:"email" json:"email" form:"email"`
	FlatsCount   int    `db:"flats_count" json:"flats_count" form:"flats_count"`
	PasswordHash []byte `db:"password_hash" json:"-" form:"-"`
}

func (o Organization) Validate() error {
	// TODO: validate organization
	return nil
}

type Operator struct {
	ID                       int    `db:"id" json:"id" form:"id"`
	OrganizationID           int    `db:"organization_id" json:"organization_id" form:"organization_id"`
	Phone                    string `db:"phone" json:"phone" form:"phone"`
	PasswordHash             []byte `db:"password_hash" json:"-" form:"-"`
	Name                     string `db:"name" json:"name" form:"name"`
	ResponsibleCategoriesStr string `db:"-" json:"-" form:"responsible_categories"`
	ResponsibleCategories    []int  `db:"responsible_categories" json:"responsible_categories" form:"-"`
}

func (o Operator) Validate() error {
	// TODO: validate operator
	return nil
}

type Owner struct {
	ID             int    `db:"id" json:"id" form:"id"`
	OrganizationID int    `db:"organization_id" json:"organization_id" form:"organization_id"`
	Phone          string `db:"phone" json:"phone" form:"phone"`
	PasswordHash   []byte `db:"password_hash" json:"-" form:"-"`
	Name           string `db:"name" json:"name" form:"name"`
	Address        string `db:"address" json:"address" form:"address"`
}

func (u Owner) Validate() error {
	// TODO: validate user
	return nil
}

type Request struct {
	ID             int       `db:"id" json:"id" form:"id"`
	OrganizationID int       `db:"organization_id" json:"organization_id" form:"-"`
	OwnerID        int       `db:"owner_id" json:"owner_id" form:"-"`
	OperatorID     *int      `db:"operator_id" json:"operator_id" form:"-"`
	CategoryID     *int      `db:"category_id" json:"category_id" form:"-"`
	Text           string    `db:"text" json:"text" form:"text"`
	Response       *string   `db:"response" json:"response" form:"response"`
	Status         string    `db:"status" json:"status" form:"status"`
	CreatedAt      time.Time `db:"created_at" json:"created_at" form:"-"`
}

type RequestExtended struct {
	Request `db:",inline"`

	CategoryName *string `db:"category_name"`

	OperatorPhone *string `db:"operator_phone"`
	OperatorName  *string `db:"operator_name"`

	OwnerPhone   *string `db:"owner_phone"`
	OwnerName    *string `db:"owner_name"`
	OwnerAddress *string `db:"owner_address"`
}

func (r Request) Validate() error {
	// TODO: validate request
	return nil
}

func (r Request) HasNewStatus() bool {
	return r.Status == status.New
}

func (r Request) HasInProgressStatus() bool {
	return r.Status == status.InProgress
}
