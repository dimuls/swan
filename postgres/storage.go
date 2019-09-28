package postgres

import (
	"errors"
	"time"

	"github.com/Boostport/migration"
	"github.com/Boostport/migration/driver/postgres"
	"github.com/gobuffalo/packr"
	"github.com/jmoiron/sqlx"

	"github.com/dimuls/swan/entity"
)

type Storage struct {
	uri string
	db  *sqlx.DB
}

func NewStorage(uri string) (*Storage, error) {
	db, err := sqlx.Open("postgres", uri)
	if err != nil {
		return nil, errors.New("failed to open DB: " + err.Error())
	}

	err = db.Ping()
	if err != nil {
		return nil, errors.New("failed to ping DB: " + err.Error())
	}

	return &Storage{uri: uri, db: db}, nil
}

//go:generate packr

const migrationsPath = "./migrations"

func (s *Storage) Migrate() error {
	packrSource := &migration.PackrMigrationSource{
		Box: packr.NewBox(migrationsPath),
	}

	d, err := postgres.New(s.uri)
	if err != nil {
		return errors.New("failed to create migration driver: " + err.Error())
	}

	_, err = migration.Migrate(d, packrSource, migration.Up, 0)
	if err != nil {
		return errors.New("failed to migrate: " + err.Error())
	}

	return nil
}

func (s *Storage) PasswordCode(role string, login string) (
	pc entity.PasswordCode, err error) {
	err = s.db.QueryRowx(`
		SELECT * FROM password_codes WHERE role = $1 AND login = $2
	`, role, login).StructScan(&pc)
	return
}

func (s *Storage) UpsertPasswordCode(pc entity.PasswordCode) error {
	_, err := s.db.Exec(`
		INSERT INTO password_codes (role, login, code, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO UPDATE SET code = $3, created_at = $5
	`, pc.Role, pc.Login, pc.Code, pc.CreatedAt)
	return err
}

func (s *Storage) Admin(email string) (a entity.Admin, err error) {
	err = s.db.QueryRowx(`SELECT * FROM admins WHERE email = $1`, email).
		StructScan(&a)
	return
}

func (s *Storage) SetAdminPasswordHash(adminID int, passwordHash []byte) error {
	_, err := s.db.Exec(`
		UPDATE admins SET password_hash = $1 WHERE id = $2
    `, passwordHash, adminID)
	return err
}

func (s *Storage) Categories() (cs []entity.Category, err error) {
	err = s.db.Select(&cs, `SELECT * FROM categories`)
	return
}

func (s *Storage) AddCategory(c entity.Category) (entity.Category, error) {
	err := s.db.QueryRowx(`
		INSERT INTO categories (name) VALUES ($1) RETURNING id
	`, c.Name).Scan(&c.ID)
	return c, err
}

func (s *Storage) SetCategory(c entity.Category) (entity.Category, error) {
	_, err := s.db.Exec(`UPDATE categories SET name = $1 WHERE id = $2`,
		c.Name, c.ID)
	return c, err
}

func (s *Storage) RemoveCategory(id int) error {
	_, err := s.db.Exec(`DELETE FROM categories WHERE id = $1`, id)
	return err
}

func (s *Storage) CategorySamples() (css []entity.CategorySample, err error) {
	err = s.db.Select(&css, `SELECT * FROM category_samples`)
	return
}

func (s *Storage) SetCategorySamples(css []entity.CategorySample) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec(`DELETE FROM category_samples`)
	if err != nil {
		tx.Rollback()
		return err
	}

	for _, cs := range css {
		_, err = tx.Exec(`
			INSERT INTO category_samples (category_id, text)
			VALUES ($1, $2)
		`, cs.CategoryID, cs.Text)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		tx.Rollback()
	}

	return err
}

func (s *Storage) Organization(email string) (o entity.Organization, err error) {
	err = s.db.QueryRowx(`SELECT * FROM organizations WHERE email = $1`,
		email).StructScan(&o)
	return
}

func (s *Storage) Organizations() (os []entity.Organization, err error) {
	err = s.db.Select(&os, `SELECT * FROM organizations`)
	return
}

func (s *Storage) AddOrganization(o entity.Organization) (entity.Organization, error) {
	err := s.db.QueryRowx(`
		INSERT INTO organizations (name, email, flats_count, password_hash)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, o.Name, o.Email, o.FlatsCount, o.PasswordHash).Scan(&o.ID)
	return o, err
}

func (s *Storage) SetOrganization(o entity.Organization) (entity.Organization, error) {
	_, err := s.db.Exec(`
		UPDATE organizations SET name = $1, email = $2, flats_count = $3,
			password_hash = $4
		WHERE id = $5
	`, o.Name, o.Email, o.FlatsCount, o.PasswordHash, o.ID)
	return o, err
}

func (s *Storage) RemoveOrganization(id int) error {
	_, err := s.db.Exec(`DELETE FROM organizations WHERE id = $1`, id)
	return err
}

func (s *Storage) SetOrganizationPasswordHash(organizationID int,
	passwordHash []byte) error {
	_, err := s.db.Exec(`
		UPDATE organizations SET password_hash = $1 WHERE id = $2
    `, passwordHash, organizationID)
	return err
}

func (s *Storage) Operator(phone string) (o entity.Operator, err error) {
	err = s.db.QueryRowx(`SELECT * FROM operators WHERE phone = $1`,
		phone).StructScan(&o)
	return
}

func (s *Storage) OrganizationOperators(organizationID int) (
	os []entity.Operator, err error) {
	err = s.db.Select(&os, `
		SELECT * FROM operators WHERE organization_id = $1
	`, organizationID)
	return
}

func (s *Storage) AddOperator(o entity.Operator) (entity.Operator, error) {
	err := s.db.QueryRowx(`
		INSERT INTO operators (organization_id, phone, password_hash, name,
			responsible_categories)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`).Scan(&o.ID)
	return o, err
}

func (s *Storage) SetOperator(o entity.Operator) (entity.Operator, error) {
	_, err := s.db.Exec(`
		UPDATE operators SET phone = $1, password_hash = $2, name = $3,
			responsible_categories = $4
		WHERE id = $5
	`, o.Phone, o.PasswordHash, o.Name, o.ResponsibleCategories, o.ID)
	return o, err
}

func (s *Storage) RemoveOrganizationOperator(
	organizationID int, operatorID int) error {
	_, err := s.db.Exec(`
		DELETE FROM organizations
		WHERE organization_id = $1 AND operator_id = $2
	`, organizationID, operatorID)
	return err
}

func (s *Storage) FindOrganizationOperator(organizationID, categoryID int) (
	o entity.Operator, err error) {
	err = s.db.QueryRowx(`
		SELECT * FROM operators WHERE organization_id = $1
			AND $2 = ANY(responsible_categories)
	`, organizationID, categoryID).StructScan(&o)
	return
}

func (s *Storage) SetOperatorPasswordHash(operatorID int,
	passwordHash []byte) error {
	_, err := s.db.Exec(`
		UPDATE operators SET password_hash = $1 WHERE id = $2
    `, passwordHash, operatorID)
	return err
}

func (s *Storage) Owner(phone string) (o entity.Owner, err error) {
	err = s.db.QueryRowx(`SELECT * FROM owners WHERE phone = $1`,
		phone).StructScan(&o)
	return
}

func (s *Storage) OrganizationOwners(organizationID int) (os []entity.Owner, err error) {
	err = s.db.Select(&os, `
		SELECT * FROM owners WHERE organization_id = $1
	`, organizationID)
	return
}

func (s *Storage) AddOwner(o entity.Owner) (entity.Owner, error) {
	err := s.db.QueryRowx(`
		INSERT INTO owners
			(organization_id, phone, password_hash, name, address)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`).Scan(&o.ID)
	return o, err
}

func (s *Storage) SetOwner(o entity.Owner) (entity.Owner, error) {
	_, err := s.db.Exec(`
		UPDATE owners SET phone = $1, password_hash = $2, name = $3,
			address = $4 WHERE id = $5
	`, o.Phone, o.PasswordHash, o.Name, o.Address, o.ID)
	return o, err
}

func (s *Storage) RemoveOrganizationOwner(organizationID int,
	ownerID int) error {
	_, err := s.db.Exec(`
		DELETE FROM owners WHERE organization_id = $1 AND id = $2
	`, organizationID, ownerID)
	return err
}

func (s *Storage) SetOwnerPasswordHash(ownerID int,
	passwordHash []byte) error {
	_, err := s.db.Exec(`
		UPDATE owners SET password_hash = $1 WHERE id = $2 
    `, passwordHash, ownerID)
	return err
}

func (s *Storage) OperatorRequests(operatorID int) (
	rs []entity.Request, err error) {
	err = s.db.Select(&rs, `
		SELECT * FROM requests WHERE operator_id = $1
	`, operatorID)
	return
}

func (s *Storage) SetOperatorRequest(operatorID int, r entity.Request) (
	entity.Request, error) {
	_, err := s.db.Exec(`
		UPDATE requests SET category_id = $1, response = $2, status = $3
		WHERE operator_id = $4 AND id = $5
	`, r.CategoryID, r.Response, r.Status, operatorID, r.ID)
	return r, err
}

func (s *Storage) OwnerRequests(ownerID int) (rs []entity.Request, err error) {
	err = s.db.Select(&rs, `
		SELECT * FROM requests WHERE owner_id = $1
	`, ownerID)
	return
}

func (s *Storage) AddRequest(r entity.Request) (entity.Request, error) {
	err := s.db.QueryRowx(`
		INSERT INTO request 
			(organization_id, owner_id, operator_id, category_id, text, 
				status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`, r.OrganizationID, r.OwnerID, r.OperatorID, r.CategoryID, r.Text,
		r.Status, time.Now()).Scan(&r.ID)
	return r, err
}
