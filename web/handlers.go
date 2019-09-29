package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"golang.org/x/crypto/bcrypt"

	"github.com/dimuls/swan/entity"
	"github.com/dimuls/swan/entity/role"
)

type loginData struct {
	Role     string
	Login    string
	Password string
}

func (ld loginData) Validate() error {
	err := role.Validate(ld.Role)
	if err != nil {
		return err
	}
	// TODO: validate other fields
	return nil
}

func (s *Server) postAPILogin(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	var ld loginData

	err = c.Bind(&ld)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind login data: "+err.Error())
	}

	err = ld.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate login data: "+err.Error())
	}

	var e interface{}

	switch ld.Role {
	case role.Admin:
		e, err = s.storage.Admin(ld.Login)
	case role.Organization:
		e, err = s.storage.Organization(ld.Login)
	case role.Operator:
		e, err = s.storage.Operator(ld.Login)
	case role.Owner:
		e, err = s.storage.Owner(ld.Login)
	}
	if err != nil {
		return errors.New("failed to get entity from storage: " + err.Error())
	}

	switch et := e.(type) {
	case entity.Admin:
		if et.PasswordHash == nil {
			return echo.NewHTTPError(http.StatusFound,
				"password reset required")
		}

		if bcrypt.CompareHashAndPassword(et.PasswordHash,
			[]byte(ld.Password)) != nil {
			return echo.NewHTTPError(http.StatusUnauthorized)
		}

		sess.Values["role"] = role.Admin
		sess.Values["login"] = et.Email
		sess.Values["admin_id"] = et.ID

	case entity.Organization:
		if et.PasswordHash == nil {
			return echo.NewHTTPError(http.StatusFound,
				"password reset required")
		}

		if bcrypt.CompareHashAndPassword(et.PasswordHash,
			[]byte(ld.Password)) != nil {
			return echo.NewHTTPError(http.StatusUnauthorized)
		}

		sess.Values["role"] = role.Organization
		sess.Values["login"] = et.Email
		sess.Values["organization_id"] = et.ID

	case entity.Operator:
		if et.PasswordHash == nil {
			return echo.NewHTTPError(http.StatusFound,
				"password reset required")
		}

		if bcrypt.CompareHashAndPassword(et.PasswordHash,
			[]byte(ld.Password)) != nil {
			return echo.NewHTTPError(http.StatusUnauthorized)
		}

		sess.Values["role"] = role.Operator
		sess.Values["login"] = et.Phone
		sess.Values["operator_id"] = et.ID

	case entity.Owner:
		if et.PasswordHash == nil {
			return echo.NewHTTPError(http.StatusFound,
				"password reset required")
		}

		if bcrypt.CompareHashAndPassword(et.PasswordHash,
			[]byte(ld.Password)) != nil {
			return echo.NewHTTPError(http.StatusUnauthorized)
		}

		sess.Values["role"] = role.Owner
		sess.Values["login"] = et.Phone
		sess.Values["owner_id"] = et.ID
		sess.Values["organization_id"] = et.OrganizationID
	}

	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		return errors.New("failed to save session: " + err.Error())
	}

	return c.NoContent(http.StatusOK)
}

func generatePasswordCode() string {
	// TODO
	return "4242"
}

func (s *Server) postAPIPasswordCode(c echo.Context) error {
	var passwordCodeData struct {
		Role  string
		Login string
	}

	err := c.Bind(&passwordCodeData)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind password data: "+err.Error())
	}

	err = role.Validate(passwordCodeData.Role)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate role: "+err.Error())
	}

	pc := entity.PasswordCode{
		Role:      passwordCodeData.Role,
		Login:     passwordCodeData.Login,
		Code:      generatePasswordCode(),
		CreatedAt: time.Now(),
	}

	err = s.storage.UpsertPasswordCode(pc)
	if err != nil {
		return errors.New("failed to upsert password code: " + err.Error())
	}

	var e interface{}

	switch pc.Role {
	case role.Admin:
		e, err = s.storage.Admin(pc.Login)
	case role.Organization:
		e, err = s.storage.Organization(pc.Login)
	case role.Operator:
		e, err = s.storage.Operator(pc.Login)
	case role.Owner:
		e, err = s.storage.Owner(pc.Login)
	}
	if err != nil {
		return errors.New("failed to get entity from storage: " + err.Error())
	}

	switch et := e.(type) {
	case entity.Admin:
		err = s.emailSender.SendEmail(et.Email, "password reset code: "+pc.Code)
	case entity.Organization:
		err = s.emailSender.SendEmail(et.Email, "password reset code: "+pc.Code)
	case entity.Operator:
		err = s.smsSender.SendSMS(et.Phone, "password reset code: "+pc.Code)
	case entity.Owner:
		err = s.smsSender.SendSMS(et.Phone, "password reset code: "+pc.Code)
	}
	if err != nil {
		return errors.New("failed to send password code: " +
			err.Error())
	}

	return c.NoContent(http.StatusOK)
}

func (s *Server) postAPIPassword(c echo.Context) error {
	var passwordData struct {
		Role     string
		Login    string
		Code     string
		Password string
	}

	err := c.Bind(&passwordData)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind password data: "+err.Error())
	}

	err = role.Validate(passwordData.Role)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate role: "+err.Error())
	}

	var e interface{}

	switch passwordData.Role {
	case role.Admin:
		e, err = s.storage.Admin(passwordData.Login)
	case role.Organization:
		e, err = s.storage.Organization(passwordData.Login)
	case role.Operator:
		e, err = s.storage.Operator(passwordData.Login)
	case role.Owner:
		e, err = s.storage.Owner(passwordData.Login)
	}
	if err != nil {
		return errors.New("failed to get entity from storage: " + err.Error())
	}

	var pc entity.PasswordCode

	switch et := e.(type) {
	case entity.Admin:
		pc, err = s.storage.PasswordCode(passwordData.Role, et.Email)
	case entity.Organization:
		pc, err = s.storage.PasswordCode(passwordData.Role, et.Email)
	case entity.Operator:
		pc, err = s.storage.PasswordCode(passwordData.Role, et.Phone)
	case entity.Owner:
		pc, err = s.storage.PasswordCode(passwordData.Role, et.Phone)
	}
	if err != nil {
		return errors.New("failed to get password code from storage: " +
			err.Error())
	}

	if time.Now().Sub(pc.CreatedAt) < 1*time.Hour {
		return echo.NewHTTPError(http.StatusForbidden)
	}

	if pc.Code != passwordData.Code {
		return echo.NewHTTPError(http.StatusForbidden)
	}

	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(passwordData.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("failed to generate password hash: " + err.Error())
	}

	switch et := e.(type) {
	case entity.Admin:
		err = s.storage.RemovePasswordCode(role.Admin, et.Email)
	case entity.Organization:
		err = s.storage.RemovePasswordCode(role.Organization, et.Email)
	case entity.Operator:
		err = s.storage.RemovePasswordCode(role.Operator, et.Phone)
	case entity.Owner:
		err = s.storage.RemovePasswordCode(role.Owner, et.Phone)
	}
	if err != nil {
		return errors.New("failed to remove password code from storage: " +
			err.Error())
	}

	switch et := e.(type) {
	case entity.Admin:
		err = s.storage.SetAdminPasswordHash(et.ID, passwordHash)
	case entity.Organization:
		err = s.storage.SetOrganizationPasswordHash(et.ID, passwordHash)
	case entity.Operator:
		err = s.storage.SetOperatorPasswordHash(et.ID, passwordHash)
	case entity.Owner:
		err = s.storage.SetOwnerPasswordHash(et.ID, passwordHash)
	}
	if err != nil {
		return errors.New("failed to set entity password hash in storage: " +
			err.Error())
	}

	return c.NoContent(http.StatusOK)
}

func (s *Server) getAPIEntity(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	r, ok := sess.Values["role"].(string)
	if !ok {
		return errors.New("failed to get role from session")
	}

	login, ok := sess.Values["login"].(string)
	if !ok {
		return errors.New("failed to get login from session")
	}

	var e interface{}

	switch r {
	case role.Admin:
		e, err = s.storage.Admin(login)
	case role.Organization:
		e, err = s.storage.Organization(login)
	case role.Operator:
		e, err = s.storage.Operator(login)
	case role.Owner:
		e, err = s.storage.Owner(login)
	}
	if err != nil {
		return errors.New("failed to get entity from storage: " + err.Error())
	}

	return c.JSON(http.StatusOK, e)
}

func (s *Server) getAPICategories(c echo.Context) error {
	cs, err := s.storage.Categories()
	if err != nil {
		return errors.New("failed to get categories from storage: " +
			err.Error())
	}

	if cs == nil {
		cs = []entity.Category{}
	}

	return c.JSON(http.StatusOK, cs)
}

func (s *Server) postAPICategories(c echo.Context) error {
	var ct entity.Category

	err := c.Bind(&ct)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind category: "+err.Error())
	}

	err = ct.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate category: "+err.Error())
	}

	ct, err = s.storage.AddCategory(ct)
	if err != nil {
		return errors.New("failed to add category to storage: " + err.Error())
	}

	return c.JSON(http.StatusOK, ct)
}

func (s *Server) putAPICategory(c echo.Context) error {
	categoryID, err := strconv.Atoi(c.Param("category_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to parse category_id: "+err.Error())
	}

	var ct entity.Category

	err = c.Bind(&ct)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind category: "+err.Error())
	}

	err = ct.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate category: "+err.Error())
	}

	ct.ID = categoryID

	ct, err = s.storage.SetCategory(ct)
	if err != nil {
		return errors.New("failed to set category in storage: " + err.Error())
	}

	return c.JSON(http.StatusOK, ct)
}

func (s *Server) deleteAPICategory(c echo.Context) error {
	categoryID, err := strconv.Atoi(c.Param("category_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to parse category_id: "+err.Error())
	}

	err = s.storage.RemoveCategory(categoryID)
	if err != nil {
		return errors.New("failed to remove category from storage: " +
			err.Error())
	}

	return c.NoContent(http.StatusOK)
}

func (s *Server) postAPICategorySamples(c echo.Context) error {
	var samples []entity.CategorySample

	err := c.Bind(&samples)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind category samples: "+err.Error())
	}

	for i, s := range samples {
		err := s.Validate()
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest,
				fmt.Sprintf("failed to validate sample %d", i))
		}
	}

	err = s.storage.SetCategorySamples(samples)
	if err != nil {
		return errors.New("failed to set category samples: " + err.Error())
	}

	return c.NoContent(http.StatusOK)
}

func (s *Server) postAPICategorySamplesClassifier(c echo.Context) error {
	samples, err := s.storage.CategorySamples()
	if err != nil {
		return errors.New("failed to get category samples from storage: " +
			err.Error())
	}

	err = s.classifier.Train(samples)
	if err != nil {
		return errors.New("failed to train classifier: " + err.Error())
	}

	return c.NoContent(http.StatusOK)
}

func (s *Server) getAPICategorySamplesClassifierTraining(c echo.Context) error {
	training, err := s.classifier.Training()
	if err != nil {
		return errors.New("failed to get training from classifier: " +
			err.Error())
	}

	return c.JSON(http.StatusOK, training)
}

func (s *Server) getAPIOrganizations(c echo.Context) error {
	os, err := s.storage.Organizations()
	if err != nil {
		return errors.New("failed to get organizations from storage: " +
			err.Error())
	}

	if os == nil {
		os = []entity.Organization{}
	}

	return c.JSON(http.StatusOK, os)
}

func (s *Server) postAPIOrganizations(c echo.Context) error {
	var o entity.Organization

	err := c.Bind(&o)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind organization")
	}

	err = o.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate organization: "+err.Error())
	}

	o, err = s.storage.AddOrganization(o)
	if err != nil {
		return errors.New("failed to add organization to storage: " + err.Error())
	}

	return c.JSON(http.StatusOK, o)
}

func (s *Server) putAPIOrganization(c echo.Context) error {
	organizationID, err := strconv.Atoi(c.Param("organization_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to parse organization_id: "+err.Error())
	}

	var o entity.Organization

	err = c.Bind(&o)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind organization")
	}

	err = o.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate organization: "+err.Error())
	}

	o.ID = organizationID

	o, err = s.storage.SetOrganization(o)
	if err != nil {
		return errors.New("failed to add organization to storage: " + err.Error())
	}

	return c.JSON(http.StatusOK, o)
}

func (s *Server) deleteAPIOrganization(c echo.Context) error {
	organizationID, err := strconv.Atoi(c.Param("organization_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to parse organization_id: "+err.Error())
	}

	err = s.storage.RemoveOrganization(organizationID)
	if err != nil {
		return errors.New("failed to remove organization from storage: " +
			err.Error())
	}

	return c.NoContent(http.StatusOK)
}

func (s *Server) getAPIOperators(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	organizationID, ok := sess.Values["organization_id"].(int)
	if !ok {
		return errors.New("failed to get organization ID from session")
	}

	os, err := s.storage.OrganizationOperators(organizationID)
	if err != nil {
		return errors.New("failed to get organization operators from storage: " +
			err.Error())
	}

	return c.JSON(http.StatusOK, os)
}

func (s *Server) postAPIOperators(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	organizationID, ok := sess.Values["organization_id"].(int)
	if !ok {
		return errors.New("failed to get organization ID from session")
	}

	var o entity.Operator

	err = c.Bind(&o)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind operator: "+err.Error())
	}

	err = o.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate operator: "+err.Error())
	}

	o.OrganizationID = organizationID

	o, err = s.storage.AddOperator(o)
	if err != nil {
		return errors.New("failed to add operator to storage: " + err.Error())
	}

	return c.JSON(http.StatusOK, o)
}

func (s *Server) putAPIOperator(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	organizationID, ok := sess.Values["organization_id"].(int)
	if !ok {
		return errors.New("failed to get organization ID from session")
	}

	operatorID, err := strconv.Atoi(c.Param("operator_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to parse operator_id: "+err.Error())
	}

	var o entity.Operator

	err = c.Bind(&o)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind operator: "+err.Error())
	}

	err = o.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate operator: "+err.Error())
	}

	o.ID = operatorID
	o.OrganizationID = organizationID

	o, err = s.storage.SetOperator(o)
	if err != nil {
		return errors.New("failed to set operator to storage: " + err.Error())
	}

	return c.JSON(http.StatusOK, o)
}

func (s *Server) deleteAPIOperator(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	organizationID, ok := sess.Values["organization_id"].(int)
	if !ok {
		return errors.New("failed to get organization ID from session")
	}

	operatorID, err := strconv.Atoi(c.Param("operator_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to parse operator_id: "+err.Error())
	}

	err = s.storage.RemoveOrganizationOperator(organizationID, operatorID)
	if err != nil {
		return errors.New("failed to remove organization operator from storage: " +
			err.Error())
	}

	return c.NoContent(http.StatusOK)
}

func (s *Server) getAPIOwners(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	organizationID, ok := sess.Values["organization_id"].(int)
	if !ok {
		return errors.New("failed to get organization ID from session")
	}

	os, err := s.storage.OrganizationOwners(organizationID)
	if err != nil {
		return errors.New("failed to get organization owners from storage: " +
			err.Error())
	}

	return c.JSON(http.StatusOK, os)
}

func (s *Server) postAPIOwners(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	organizationID, ok := sess.Values["organization_id"].(int)
	if !ok {
		return errors.New("failed to get organization ID from session")
	}

	var o entity.Owner

	err = c.Bind(&o)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind owner: "+err.Error())
	}

	err = o.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate owner: "+err.Error())
	}

	o.OrganizationID = organizationID

	o, err = s.storage.AddOwner(o)
	if err != nil {
		return errors.New("failed to add owner to storage: " + err.Error())
	}

	return c.JSON(http.StatusOK, o)
}

func (s *Server) putAPIOwner(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	organizationID, ok := sess.Values["organization_id"].(int)
	if !ok {
		return errors.New("failed to get organization ID from session")
	}

	ownerID, err := strconv.Atoi(c.Param("owner_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to parse owner_id: "+err.Error())
	}

	var o entity.Owner

	err = c.Bind(&o)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind owner: "+err.Error())
	}

	err = o.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate owner: "+err.Error())
	}

	o.ID = ownerID
	o.OrganizationID = organizationID

	o, err = s.storage.SetOwner(o)
	if err != nil {
		return errors.New("failed to set owner to storage: " + err.Error())
	}

	return c.JSON(http.StatusOK, o)
}

func (s *Server) deleteAPIOwner(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	organizationID, ok := sess.Values["organization_id"].(int)
	if !ok {
		return errors.New("failed to get organization ID from session")
	}

	ownerID, err := strconv.Atoi(c.Param("owner_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to parse owner_id: "+err.Error())
	}

	err = s.storage.RemoveOrganizationOwner(organizationID, ownerID)
	if err != nil {
		return errors.New(
			"failed to remove organization owner from storage: " + err.Error())
	}

	return c.NoContent(http.StatusOK)
}

func (s *Server) getAPIOperatorsRequests(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	operatorID, ok := sess.Values["operator_id"].(int)
	if !ok {
		return errors.New("failed to get operator ID from session")
	}

	rs, err := s.storage.OperatorRequests(operatorID)
	if err != nil {
		return errors.New("failed to get operator requests from storage: " +
			err.Error())
	}

	return c.JSON(http.StatusOK, rs)
}

func (s *Server) putAPIOperatorsRequest(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	operatorID, ok := sess.Values["operator_id"].(int)
	if !ok {
		return errors.New("failed to get operator ID from session")
	}

	var r entity.Request

	err = c.Bind(&r)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind request: "+err.Error())
	}

	err = r.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate request: "+err.Error())
	}

	r, err = s.storage.SetOperatorRequest(operatorID, r)
	if err != nil {
		return errors.New("failed to set operator request in storage: " +
			err.Error())
	}

	return c.JSON(http.StatusOK, r)
}

func (s *Server) getAPIOwnersRequests(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	ownerID, ok := sess.Values["owner_id"].(int)
	if !ok {
		return errors.New("failed to get owner ID from session")
	}

	rs, err := s.storage.OwnerRequests(ownerID)
	if err != nil {
		return errors.New("failed to get owner requests: " + err.Error())
	}

	return c.JSON(http.StatusOK, rs)
}

func (s *Server) postAPIOwnersRequests(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	ownerID, ok := sess.Values["owner_id"].(int)
	if !ok {
		return errors.New("failed to get owner ID from session")
	}

	organizationID, ok := sess.Values["organization_id"].(int)
	if !ok {
		return errors.New("failed to get organization ID from session")
	}

	var r entity.Request

	err = c.Bind(&r)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			errors.New("failed to bind request: "+err.Error()))
	}

	err = r.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			errors.New("failed to validate request: "+err.Error()))
	}

	r.OrganizationID = organizationID
	r.OwnerID = ownerID

	categoryID, err := s.classifier.Classify(r.Text)
	if err != nil {
		s.log.WithError(err).Error("failed to classify category")
	} else {
		r.CategoryID = &categoryID
	}

	o, err := s.storage.FindOrganizationOperator(
		organizationID, categoryID)
	if err != nil {
		s.log.WithError(err).Error(
			"failed to find organization operator for request: " + err.Error())
	} else {
		r.OperatorID = &o.ID
	}

	r, err = s.storage.AddRequest(r)
	if err != nil {
		return errors.New("failed to add request to storage: " + err.Error())
	}

	return c.JSON(http.StatusOK, r)
}
