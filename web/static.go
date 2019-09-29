package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"golang.org/x/crypto/bcrypt"

	"github.com/dimuls/swan/entity"
	"github.com/dimuls/swan/entity/role"
	"github.com/dimuls/swan/entity/status"
)

func (s *Server) getIndex(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	rl, ok := sess.Values["role"].(string)
	if !ok {
		return c.Redirect(http.StatusFound, "/login")
	}

	switch rl {
	case role.Admin:
		return c.Redirect(http.StatusFound, "/admin")
	case role.Organization:
		return c.Redirect(http.StatusFound, "/organization")
	case role.Operator:
		return c.Redirect(http.StatusFound, "/operator")
	case role.Owner:
		return c.Redirect(http.StatusFound, "/owner")
	}

	return echo.NewHTTPError(http.StatusNotFound)
}

const loginPage = `<!DOCTYPE html><html><head> <title>ЖКХ Пульс / Логин</title> <style> * { box-sizing: border-box; } body { margin: 0; font-family: Arial; } .main-cell { height: 100vh; display: flex; align-items: center; justify-content: center; } .main-cell__wrap { width: 520px; padding: 50px 45px; border: 1px solid #F4F4F4; border-radius: 14px; } .main-cell__image { display: flex; justify-content: center; } .main-cell__link { color: #6A6A66; } .main-cell__radio { margin: 15px 0; } .main-cell__radio-cell { display: inline-flex; align-items: center; margin-bottom: 5px; margin-right: 15px; } .main-cell__radio-cell input { -webkit-appearance: none; position: absolute; } .main-cell__radio-cell input+div { position: relative; display: inline-block; width: 16px; height: 16px; border: 2px solid #656565; margin-right: 5px; cursor: pointer; } .main-cell__radio-cell input+div::before { display: none; content: ""; position: absolute; top: 50%; left: 50%; width: 5px; height: 5px; margin-top: -2.5px; margin-left: -2.5px; background-color: #656565; } .main-cell__radio-cell input:checked+div::before { display: block; } .main-cell__radio-cell label { cursor: pointer; } .main-cell__input-cell input { width: 100%; padding: 25px; margin-bottom: 5px; background-color: #EFF0F3; color: #6A6A66; font-size: 16px; border: none; } .main-cell__button button { cursor: pointer; color: #ffffff; background-color: #00B858; width: 100%; padding: 25px; font-size: 26px; border: none; } .main-cell__button button:hover { background-color: #000; } </style></head><body> <div class="main-cell"> <div class="main-cell__wrap"> <div class="main-cell__image"> <div> <img src="https://svgshare.com/i/FDG.svg" width="435" alt="logo"> </div> </div> <a class="main-cell__link" href="/register">Регистрация</a> <div class="main-cell__form"> <form method="POST" action="/login"> <div class="main-cell__radio"> <div class="main-cell__radio-cell"> <input type="radio" name="role" id="role-owner" value="owner" checked /> <div></div> <label for="role-owner">Собственник</label> </div> <div class="main-cell__radio-cell"> <input type="radio" name="role" id="role-operator" value="operator" /> <div></div> <label for="role-operator">Оператор</label> </div> <div class="main-cell__radio-cell"> <input type="radio" name="role" id="role-organization" value="organization" /> <div></div> <label for="role-organization">Организация</label> </div> <div class="main-cell__radio-cell"> <input type="radio" name="role" id="role-admin" value="admin" /> <div></div> <label for="role-admin">Админ</label> </div> </div> <div class="main-cell__input"> <div class="main-cell__input-cell"> <input type="text" name="login" id="login" placeholder="Логин" /> </div> <div class="main-cell__input-cell"> <input type="password" name="password" id="password" placeholder="Пароль" /> </div> </div> <div class="main-cell__button"> <button type="submit">Войти</button> </div> </form> </div> </div> </div></body></html>`

func (s *Server) getLogin(c echo.Context) error {
	return c.Render(http.StatusOK, "login", nil)
}

func (s *Server) postLogin(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	var params loginData

	err = c.Bind(&params)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind params: "+err.Error())
	}

	err = params.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate login data: "+err.Error())
	}

	var e interface{}

	switch params.Role {
	case role.Admin:
		e, err = s.storage.Admin(params.Login)
	case role.Organization:
		e, err = s.storage.Organization(params.Login)
	case role.Operator:
		e, err = s.storage.Operator(params.Login)
	case role.Owner:
		e, err = s.storage.Owner(params.Login)
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
			[]byte(params.Password)) != nil {
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
			[]byte(params.Password)) != nil {
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
			[]byte(params.Password)) != nil {
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
			[]byte(params.Password)) != nil {
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

	switch params.Role {
	case role.Admin:
		return c.Redirect(http.StatusFound, "/admin")
	case role.Organization:
		return c.Redirect(http.StatusFound, "/organization")
	case role.Operator:
		return c.Redirect(http.StatusFound, "/operator")
	case role.Owner:
		return c.Redirect(http.StatusFound, "/owner")
	}

	return echo.NewHTTPError(http.StatusNotFound)
}

func (s *Server) getLogout(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	sess.Options.MaxAge = -1

	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		return errors.New("failed to save session")
	}

	return c.Redirect(http.StatusFound, "/")
}

const registerPage = `<!DOCTYPE html><html><head> <title>ЖКХ Пульс / Регистрация</title> <style> * { box-sizing: border-box; } body { margin: 0; font-family: Arial; } .main-cell { height: 100vh; display: flex; align-items: center; justify-content: center; } .main-cell__wrap { width: 520px; padding: 50px 45px; border: 1px solid #F4F4F4; border-radius: 14px; } .main-cell__image { display: flex; justify-content: center; } .main-cell__link { color: #6A6A66; } .main-cell__radio { margin: 15px 0; } .main-cell__radio-cell { display: inline-flex; align-items: center; margin-bottom: 5px; margin-right: 15px; } .main-cell__radio-cell input { -webkit-appearance: none; position: absolute; } .main-cell__radio-cell input+div { position: relative; display: inline-block; width: 16px; height: 16px; border: 2px solid #656565; margin-right: 5px; cursor: pointer; } .main-cell__radio-cell input+div::before { display: none; content: ""; position: absolute; top: 50%; left: 50%; width: 5px; height: 5px; margin-top: -2.5px; margin-left: -2.5px; background-color: #656565; } .main-cell__radio-cell input:checked+div::before { display: block; } .main-cell__radio-cell label { cursor: pointer; } .main-cell__input-cell input { width: 100%; padding: 25px; margin-bottom: 5px; background-color: #EFF0F3; color: #6A6A66; font-size: 16px; border: none; } .main-cell__button button { cursor: pointer; color: #ffffff; background-color: #00B858; width: 100%; padding: 25px; font-size: 26px; border: none; } .main-cell__button button:hover { background-color: #000; } </style></head><body> <div class="main-cell"> <div class="main-cell__wrap"> <div class="main-cell__image"> <div> <img src="https://svgshare.com/i/FDG.svg" width="435" alt="logo"> </div> </div> <div class="main-cell__form"> <form method="POST" action="/register"> <div class="main-cell__radio"> <div class="main-cell__radio-cell"> <input type="radio" name="role" id="role-owner" value="owner" /> <div></div> <label for="role-owner">Собственник</label> </div> <div class="main-cell__radio-cell"> <input type="radio" name="role" id="role-operator" value="operator" /> <div></div> <label for="role-operator">Оператор</label> </div> <div class="main-cell__radio-cell"> <input type="radio" name="role" id="role-organization" value="organization" /> <div></div> <label for="role-organization">Организация</label> </div> <div class="main-cell__radio-cell"> <input type="radio" name="role" id="role-admin" value="admin" /> <div></div> <label for="role-admin">Админ</label> </div> </div> <div class="main-cell__input"> <div class="main-cell__input-cell"> <input type="text" name="login" id="login" placeholder="Логин" /> </div> </div> <div class="main-cell__button"> <button type="submit">Получить код регистрации</button> </div> </form> </div> </div> </div></body></html>`

func (s *Server) getRegister(c echo.Context) error {
	return c.Render(http.StatusOK, "register", nil)
}

func (s *Server) postRegister(c echo.Context) error {
	var params struct {
		Role  string
		Login string
	}

	err := c.Bind(&params)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind params: "+err.Error())
	}

	err = role.Validate(params.Role)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate role: "+err.Error())
	}

	pc := entity.PasswordCode{
		Role:      params.Role,
		Login:     params.Login,
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

	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	sess.Values["register_role"] = params.Role
	sess.Values["register_login"] = params.Login

	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		return errors.New("failed to save session: " + err.Error())
	}

	return c.Redirect(http.StatusFound, "/password")
}

const passwordPage = `<!DOCTYPE html><html><head> <title>ЖКХ Пульс / Установка пароля</title> <style> * { box-sizing: border-box; } body { margin: 0; font-family: Arial; } .main-cell { height: 100vh; display: flex; align-items: center; justify-content: center; } .main-cell__wrap { width: 520px; padding: 50px 45px; border: 1px solid #F4F4F4; border-radius: 14px; } .main-cell__image { display: flex; justify-content: center; } .main-cell__link { color: #6A6A66; } .main-cell__radio { margin: 15px 0; } .main-cell__radio-cell { display: inline-flex; align-items: center; margin-bottom: 5px; margin-right: 15px; } .main-cell__radio-cell input { -webkit-appearance: none; position: absolute; } .main-cell__radio-cell input+div { position: relative; display: inline-block; width: 16px; height: 16px; border: 2px solid #656565; margin-right: 5px; cursor: pointer; } .main-cell__radio-cell input+div::before { display: none; content: ""; position: absolute; top: 50%; left: 50%; width: 5px; height: 5px; margin-top: -2.5px; margin-left: -2.5px; background-color: #656565; } .main-cell__radio-cell input:checked+div::before { display: block; } .main-cell__radio-cell label { cursor: pointer; } .main-cell__input-cell input { width: 100%; padding: 25px; margin-bottom: 5px; background-color: #EFF0F3; color: #6A6A66; font-size: 16px; border: none; } .main-cell__button button { cursor: pointer; color: #ffffff; background-color: #00B858; width: 100%; padding: 25px; font-size: 26px; border: none; } .main-cell__button button:hover { background-color: #000; } </style></head><body> <div class="main-cell"> <div class="main-cell__wrap"> <div class="main-cell__image"> <div> <img src="https://svgshare.com/i/FDG.svg" width="435" alt="logo"> </div> </div> <div class="main-cell__form"> <form method="POST" action="/password"> <div class="main-cell__input"> <div class="main-cell__input-cell"> <input type="text" name="code" id="code" placeholder="Код подтверждения" /> </div> </div> <div class="main-cell__input"> <div class="main-cell__input-cell"> <input type="password" name="password" id="password" placeholder="Пароль" /> </div> </div> <div class="main-cell__button"> <button type="submit">Установить пароль</button> </div> </form> </div> </div> </div></body></html>`

func (s *Server) getPassword(c echo.Context) error {
	return c.Render(http.StatusOK, "password", nil)
}

func (s *Server) postPassword(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	rl, ok := sess.Values["register_role"].(string)
	if !ok {
		return c.Redirect(http.StatusFound, "/register")
	}

	login, ok := sess.Values["register_login"].(string)
	if !ok {
		return c.Redirect(http.StatusFound, "/register")
	}

	var params struct {
		Code     string
		Password string
	}

	err = c.Bind(&params)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind params: "+err.Error())
	}

	var e interface{}

	switch rl {
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

	var pc entity.PasswordCode

	switch et := e.(type) {
	case entity.Admin:
		pc, err = s.storage.PasswordCode(rl, et.Email)
	case entity.Organization:
		pc, err = s.storage.PasswordCode(rl, et.Email)
	case entity.Operator:
		pc, err = s.storage.PasswordCode(rl, et.Phone)
	case entity.Owner:
		pc, err = s.storage.PasswordCode(rl, et.Phone)
	}
	if err != nil {
		return errors.New("failed to get password code from storage: " +
			err.Error())
	}

	if time.Now().Sub(pc.CreatedAt) < 1*time.Hour {
		return echo.NewHTTPError(http.StatusForbidden)
	}

	if pc.Code != params.Code {
		return echo.NewHTTPError(http.StatusForbidden)
	}

	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(params.Password), bcrypt.DefaultCost)
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

	delete(sess.Values, "register_role")
	delete(sess.Values, "register_login")

	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		return errors.New("failed to save session: " + err.Error())
	}

	return c.Redirect(http.StatusFound, "/login")
}

func (s *Server) getAdmin(c echo.Context) error {
	return c.Redirect(http.StatusFound, "/admin/organizations")
}

const adminOrganizationsPage = `<!DOCTYPE html><html><head> <title>ЖКХ Пульс / Админка / Организации</title> <style> * { box-sizing: border-box; } body { margin: 0; font-family: Arial; } .main-root { display: flex; } .main-root__le { height: 100vh; width: 15%; border-right: 1px solid #CCCCCC; } .main-root__user { display: block; font-size: 14px; padding: 15px; box-shadow: -8px -2px 10px rgba(0, 0, 0, 0.2) } .main-root__link { position: relative; display: block; font-size: 15px; padding: 15px 0 15px 60px; color: #4D4D4E; text-decoration: none; } .main-root__link::before { content: ""; position: absolute; top: 50%; left: 20px; display: block; width: 20px; height: 19px; margin-top: -9.5px; background-image: url(https://svgshare.com/i/FDc.svg); } .main-root__link--active, .main-root__link:hover { color: #00B858; } .main-root__ri { width: 84%; } .main-root__content { padding-top: 1%; padding-left: 1%; } .main-root__title { display: block; padding: 15px; background-color: #00B858; color: #fff; } .main-root__wrap { display: flex; } .main-root__wrap input { border: 1px solid #E0E0E0; font-size: 16px; padding: 10px 15px; margin-right: 10px; } .main-root__wrap input[name="name"] { width: 460px; } .main-root__wrap input[name="id"], .main-root__wrap input[name="flats_count"] { width: 115px; } .main-root__wrap button { cursor: pointer; border-radius: 3px; background-color: #EEEEEE; text-transform: uppercase; border: none; font-size: 14px; color: #1B1B1B; } .main-root__wrap button:hover { background-color: #00B858; color: #fff; } .main-root__delete button { padding: 10px; min-height: 41px; margin-left: 5px; } .main-root__delete button:hover { background-color: #ff0000; color: #fff; } .main-root__null { width: 125px; } .main-root__content-form { display: flex; } </style></head><body> <div class="main-root"> <div class="main-root__le"> <b class="main-root__user">{{.Login}}</b> <a class="main-root__link" href="/logout">Выход</a> <a class="main-root__link" href="/admin/classifier">Классификатор</a> </div> <div class="main-root__ri"> <b class="main-root__title">Организации</b> <div class="main-root__content"> {{range .Organizations}} <div class="main-root__content-form"> <form method="POST" action="/admin/set-organization"> <div class="main-root__wrap"> <input type="number" name="id" value="{{.ID}}" readonly /> <input type="text" name="name" value="{{.Name}}" placeholder="Имя" /> <input type="text" name="email" value="{{.Email}}" placeholder="Email" /> <input type="number" name="flats_count" value="{{.FlatsCount}}" placeholder="Кол-во жильцов" /> <button type="submit">Сохранить</button> </div> </form> <form method="POST" action="/admin/remove-organization"> <div class="main-root__wrap main-root__delete"> <input type="hidden" name="id" value="{{.ID}}"> <button type="submit">Удалить</button> </div> </form> </div> {{end}} <form method="POST" action="/admin/create-organization"> <div class="main-root__wrap"> <div class="main-root__null"></div> <input type="text" name="name" value="" placeholder="Имя" /> <input type="text" name="email" value="" placeholder="Email" /> <input type="number" name="flats_count" value="" placeholder="Кол-во жильцов" /> <button type="submit">Добавить</button> </div> </form> </div> </div> </div></body></html>`

func (s *Server) getAdminOrganizations(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	login, ok := sess.Values["login"].(string)
	if !ok {
		return errors.New("failed to get login from session")
	}

	os, err := s.storage.Organizations()
	if err != nil {
		return errors.New("failed to get organizations from store: " +
			err.Error())
	}

	return c.Render(http.StatusOK, "admin_organizations", echo.Map{
		"Login":         login,
		"Organizations": os,
	})
}

func (s *Server) postAdminCreateOrganization(c echo.Context) error {
	var o entity.Organization

	err := c.Bind(&o)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind organization: "+err.Error())
	}

	err = o.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate organization: "+err.Error())
	}

	_, err = s.storage.AddOrganization(o)
	if err != nil {
		return errors.New("failed to create organization")
	}

	return c.Redirect(http.StatusFound, "/admin")
}

func (s *Server) postAdminSetOrganization(c echo.Context) error {
	var o entity.Organization

	err := c.Bind(&o)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind organization: "+err.Error())
	}

	err = o.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate organization: "+err.Error())
	}

	_, err = s.storage.SetOrganization(o)
	if err != nil {
		return errors.New("failed to set organization")
	}

	return c.Redirect(http.StatusFound, "/admin")
}

func (s *Server) postAdminRemoveOrganization(c echo.Context) error {
	var o entity.Organization

	err := c.Bind(&o)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind organization: "+err.Error())
	}

	err = s.storage.RemoveOrganization(o.ID)
	if err != nil {
		return errors.New("failed to remove organization")
	}

	return c.Redirect(http.StatusFound, "/admin")
}

const adminClassifierPage = `<!DOCTYPE html><html><head> <title>ЖКХ Пульс / Админка / Классификатор</title> <style> * { box-sizing: border-box; } body { margin: 0; font-family: Arial; } .main-root { display: flex; } .main-root__le { height: 100vh; width: 15%; border-right: 1px solid #CCCCCC; } .main-root__user { display: block; font-size: 14px; padding: 15px; box-shadow: -8px -2px 10px rgba(0, 0, 0, 0.2) } .main-root__link { position: relative; display: block; font-size: 15px; padding: 15px 0 15px 60px; color: #4D4D4E; text-decoration: none; } .main-root__link::before { content: ""; position: absolute; top: 50%; left: 20px; display: block; width: 20px; height: 19px; margin-top: -9.5px; background-image: url(https://svgshare.com/i/FDc.svg); } .main-root__link--active, .main-root__link:hover { color: #00B858; } .main-root__ri { width: 84%; } .main-root__content { padding-top: 1%; padding-left: 1%; } .main-root__title { display: block; padding: 15px; background-color: #00B858; color: #fff; } .main-root__wrap { display: flex; margin-bottom: 20px; } .main-root__wrap input { border: 1px solid #E0E0E0; font-size: 16px; padding: 10px 15px; margin-right: 10px; } .main-root__wrap input[name="name"] { width: 660px; } .main-root__wrap input[name="id"], .main-root__wrap input[name="flats_count"] { width: 115px; } .main-root__wrap button { cursor: pointer; border-radius: 3px; background-color: #EEEEEE; text-transform: uppercase; border: none; font-size: 14px; color: #1B1B1B; } .main-root__wrap button:hover { background-color: #00B858; color: #fff; } .main-root__delete button { padding: 10px; min-height: 41px; margin-left: 5px; } .main-root__delete button:hover { background-color: #ff0000; color: #fff; } .main-root__null { width: 125px; } .main-root__content-form { display: flex; } .main-root__txt--red { color: #ff0000; } </style></head><body> <div class="main-root"> <div class="main-root__le"> <b class="main-root__user">{{.Login}}</b> <a class="main-root__link" href="/logout">Выход</a> <a class="main-root__link" href="/admin/organizations">Организации</a> </div> <div class="main-root__ri"> <b class="main-root__title">Классификатор</b> <div class="main-root__content"> {{range .Categories}} <div class="main-root__content-form"> <form method="POST" action="/admin/classifier/set-category"> <div class="main-root__wrap"> <input type="number" name="id" value="{{.ID}}" readonly /> <input type="text" name="name" value="{{.Name}}" placeholder="Название" /> <button type="submit">Сохранить</button> </div> </form> <form method="POST" action="/admin/classifier/remove-category"> <div class="main-root__wrap main-root__delete"> <input type="hidden" name="id" value="{{.ID}}"> <button type="submit">Удалить</button> </div> </form> </div> {{end}} <form method="POST" action="/admin/classifier/create-category"> <div class="main-root__wrap"> <div class="main-root__null"></div> <input type="text" name="name" value="{{.Name}}" placeholder="Название" /> <button type="submit">Добавить</button> </div> </form> <form method="POST" action="/admin/classifier/train" enctype="multipart/form-data"> <label for="samples">Данные для тренировки</label> <div class="main-root__wrap"> <input type="file" name="samples" id="samples" {{if .Training}}disabled{{end}} /> <button type="submit">Тренировать</button> </div> </form> {{if .Training}} <b class="main-root__txt--red">Классификатор в процессе тренировки</b> {{end}} </div> </div> </div></body></html>`

func (s *Server) getAdminClassifier(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	login, ok := sess.Values["login"].(string)
	if !ok {
		return errors.New("failed to get login from session")
	}

	training, err := s.classifier.Training()
	if err != nil {
		return errors.New("failed to get classifier training: " + err.Error())
	}

	cs, err := s.storage.Categories()
	if err != nil {
		return errors.New("failed to get organizations from store: " +
			err.Error())
	}

	return c.Render(http.StatusOK, "admin_classifier", echo.Map{
		"Login":      login,
		"Training":   training,
		"Categories": cs,
	})
}

func (s *Server) postAdminCreateCategory(c echo.Context) error {
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

	_, err = s.storage.AddCategory(ct)
	if err != nil {
		return errors.New("failed to create category")
	}

	return c.Redirect(http.StatusFound, "/admin/classifier")
}

func (s *Server) postAdminSetCategory(c echo.Context) error {
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

	_, err = s.storage.SetCategory(ct)
	if err != nil {
		return errors.New("failed to set category")
	}

	return c.Redirect(http.StatusFound, "/admin/classifier")
}

func (s *Server) postAdminRemoveCategory(c echo.Context) error {
	var ct entity.Category

	err := c.Bind(&ct)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to bind category: "+err.Error())
	}

	err = s.storage.RemoveCategory(ct.ID)
	if err != nil {
		return errors.New("failed to remove category")
	}

	return c.Redirect(http.StatusFound, "/admin/classifier")
}

func (s *Server) postClassifierTrain(c echo.Context) error {
	ff, err := c.FormFile("samples")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get training data file: "+err.Error())
	}

	f, err := ff.Open()
	if err != nil {
		return errors.New("failed to open training data: " + err.Error())
	}

	var css []entity.CategorySample

	err = json.NewDecoder(f).Decode(&css)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to decode training data file: "+err.Error())
	}

	err = s.classifier.Train(css)
	if err != nil {
		return errors.New("failed to train classifier: " + err.Error())
	}

	return c.Redirect(http.StatusFound, "/admin/classifier")
}

func (s *Server) getOrganization(c echo.Context) error {
	return c.Redirect(http.StatusFound, "/organization/owners")
}

const organizationOwnersPage = `<!DOCTYPE html><html><head> <title>ЖКХ Пульс / Организация / Жильцы </title> <style> * { box-sizing: border-box; } body { margin: 0; font-family: Arial; } .main-root { display: flex; } .main-root__le { height: 100vh; width: 15%; border-right: 1px solid #CCCCCC; } .main-root__user { display: block; font-size: 14px; padding: 15px; box-shadow: -8px -2px 10px rgba(0, 0, 0, 0.2) } .main-root__link { position: relative; display: block; font-size: 15px; padding: 15px 0 15px 60px; color: #4D4D4E; text-decoration: none; } .main-root__link::before { content: ""; position: absolute; top: 50%; left: 20px; display: block; width: 20px; height: 19px; margin-top: -9.5px; background-image: url(https://svgshare.com/i/FDc.svg); } .main-root__link--active, .main-root__link:hover { color: #00B858; } .main-root__ri { width: 84%; } .main-root__content { padding-top: 1%; padding-left: 1%; } .main-root__title { display: block; padding: 15px; background-color: #00B858; color: #fff; } .main-root__wrap { display: flex; margin-bottom: 20px; } .main-root__wrap input { border: 1px solid #E0E0E0; font-size: 16px; padding: 10px 15px; margin-right: 10px; } .main-root__wrap input[name="name"] { width: 300px; } .main-root__wrap input[name="address"] { width: 550px; } .main-root__wrap input[name="id"], .main-root__wrap input[name="flats_count"] { width: 115px; } .main-root__wrap button { cursor: pointer; border-radius: 3px; background-color: #EEEEEE; text-transform: uppercase; border: none; font-size: 14px; color: #1B1B1B; } .main-root__wrap button:hover { background-color: #00B858; color: #fff; } .main-root__delete button { padding: 10px; min-height: 41px; margin-left: 5px; } .main-root__delete button:hover { background-color: #ff0000; color: #fff; } .main-root__null { width: 125px; } .main-root__content-form { display: flex; } .main-root__txt--red { color: #ff0000; } </style></head><body> <div class="main-root"> <div class="main-root__le"> <b class="main-root__user">{{.Login}}</b> <a class="main-root__link" href="/logout">Выход</a> <a class="main-root__link" href="/organization/operators">Операторы</a> </div> <div class="main-root__ri"> <b class="main-root__title">Жильцы</b> <div class="main-root__content"> {{range .Owners}} <div class="main-root__content-form"> <form method="POST" action="/organization/set-owner"> <div class="main-root__wrap"> <input type="number" name="id" value="{{.ID}}" readonly /> <input type="text" name="phone" value="{{.Phone}}" placeholder="Телефон" /> <input type="text" name="name" value="{{.Name}}" placeholder="Имя" /> <input type="text" name="address" value="{{.Address}}" placeholder="Адрес" /> <button type="submit">Сохранить</button> </div> </form> <form method="POST" action="/organization/remove-owner"> <div class="main-root__wrap main-root__delete"> <input type="hidden" name="id" value="{{.ID}}"> <button type="submit">Удалить</button> </div> </form> </div> {{end}} <form method="POST" action="/organization/create-owner"> <div class="main-root__wrap"> <div class="main-root__null"></div> <input type="text" name="phone" value="{{.Phone}}" placeholder="Телефон" /> <input type="text" name="name" value="{{.Name}}" placeholder="Имя" /> <input type="text" name="address" value="{{.Address}}" placeholder="Адрес" /> <button type="submit">Добавить</button> </div> </form> </div> </div> </div></body></html>`

func (s *Server) getOrganizationOwners(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	login, ok := sess.Values["login"].(string)
	if !ok {
		return errors.New("failed to get login from session")
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

	return c.Render(http.StatusOK, "organization_owners", echo.Map{
		"Login":  login,
		"Owners": os,
	})
}

func (s *Server) postOrganizationCreateOwner(c echo.Context) error {
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

	o.OrganizationID = organizationID

	err = o.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate owner: "+err.Error())
	}

	_, err = s.storage.AddOwner(o)
	if err != nil {
		return errors.New("failed to add owner: " + err.Error())
	}

	return c.Redirect(http.StatusFound, "/organization/owners")
}

func (s *Server) postOrganizationSetOwner(c echo.Context) error {
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

	o.OrganizationID = organizationID

	err = o.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate owner: "+err.Error())
	}

	_, err = s.storage.SetOwner(o)
	if err != nil {
		return errors.New("failed to add owner: " + err.Error())
	}

	return c.Redirect(http.StatusFound, "/organization/owners")
}

func (s *Server) postOrganizationRemoveOwner(c echo.Context) error {
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
			"failed to bind category: "+err.Error())
	}

	err = s.storage.RemoveOrganizationOwner(organizationID, o.ID)
	if err != nil {
		return errors.New("failed to remove category from storage: " +
			err.Error())
	}

	return c.Redirect(http.StatusFound, "/organization/owners")
}

const organizationOperatorsPage = `<!DOCTYPE html><html><head> <title>ЖКХ Пульс / Организация / Операторы</title> <style> * { box-sizing: border-box; } body { margin: 0; font-family: Arial; } .main-root { display: flex; } .main-root__le { height: 100vh; width: 15%; border-right: 1px solid #CCCCCC; } .main-root__user { display: block; font-size: 14px; padding: 15px; box-shadow: -8px -2px 10px rgba(0, 0, 0, 0.2) } .main-root__link { position: relative; display: block; font-size: 15px; padding: 15px 0 15px 60px; color: #4D4D4E; text-decoration: none; } .main-root__link::before { content: ""; position: absolute; top: 50%; left: 20px; display: block; width: 20px; height: 19px; margin-top: -9.5px; background-image: url(https://svgshare.com/i/FDc.svg); } .main-root__link--active, .main-root__link:hover { color: #00B858; } .main-root__ri { width: 84%; } .main-root__content { padding-top: 1%; padding-left: 1%; } .main-root__title { display: block; padding: 15px; background-color: #00B858; color: #fff; } .main-root__wrap { display: flex; margin-bottom: 20px; } .main-root__wrap input { border: 1px solid #E0E0E0; font-size: 16px; padding: 10px 15px; margin-right: 10px; } .main-root__wrap input[name="name"] { width: 300px; } .main-root__wrap input[name="address"] { width: 550px; } .main-root__wrap input[name="id"], .main-root__wrap input[name="flats_count"] { width: 115px; } .main-root__wrap button { cursor: pointer; border-radius: 3px; background-color: #EEEEEE; text-transform: uppercase; border: none; font-size: 14px; color: #1B1B1B; } .main-root__wrap button:hover { background-color: #00B858; color: #fff; } .main-root__delete button { padding: 10px; min-height: 41px; margin-left: 5px; } .main-root__delete button:hover { background-color: #ff0000; color: #fff; } .main-root__null { width: 125px; } .main-root__content-form { display: flex; } .main-root__txt--red { color: #ff0000; } </style></head><body> <div class="main-root"> <div class="main-root__le"> <b class="main-root__user">{{.Login}}</b> <a class="main-root__link" href="/logout">Выход</a> <a class="main-root__link" href="/organization/owners">Жильцы</a> </div> <div class="main-root__ri"> <b class="main-root__title">Операторы</b> <div class="main-root__content"> {{range .Operators}} <div class="main-root__content-form"> <form method="POST" action="/organization/set-operator"> <div class="main-root__wrap"> <input type="number" name="id" value="{{.ID}}" readonly /> <input type="text" name="phone" value="{{.Phone}}" placeholder="Телефон" /> <input type="text" name="name" value="{{.Name}}" placeholder="Имя" /> <input type="text" name="responsible_categories" value="{{.ResponsibleCategoriesStr}}" placeholder="Зона ответственности" /> <button type="submit">Сохранить</button> </div> </form> <form method="POST" action="/organization/remove-operator"> <div class="main-root__wrap main-root__delete"> <input type="hidden" name="id" value="{{.ID}}"> <button type="submit">Удалить</button> </div> </form> </div> {{end}} <form method="POST" action="/organization/create-operator"> <div class="main-root__wrap"> <div class="main-root__null"></div> <input type="text" name="phone" value="{{.Phone}}" placeholder="Телефон" /> <input type="text" name="name" value="{{.Name}}" placeholder="Имя" /> <input type="text" name="responsible_categories" value="{{.ResponsibleCategoriesStr}}" placeholder="Зона ответственности" /> <button type="submit">Добавить</button> </div> </form> </div> </div> </div></body></html>`

func (s *Server) getOrganizationOperators(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	login, ok := sess.Values["login"].(string)
	if !ok {
		return errors.New("failed to get login from session")
	}

	organizationID, ok := sess.Values["organization_id"].(int)
	if !ok {
		return errors.New("failed to get organization ID from session")
	}

	os, err := s.storage.OrganizationOperators(organizationID)
	if err != nil {
		return errors.New("failed to get organization owners from storage: " +
			err.Error())
	}

	for i := range os {
		var idStrs []string
		for _, id := range os[i].ResponsibleCategories {
			idStrs = append(idStrs, strconv.Itoa(id))
		}
		os[i].ResponsibleCategoriesStr = strings.Join(idStrs, ", ")
	}

	return c.Render(http.StatusOK, "organization_operators", echo.Map{
		"Login":     login,
		"Operators": os,
	})
}

func (s *Server) postOrganizationCreateOperator(c echo.Context) error {
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
			"failed to bind owner: "+err.Error())
	}

	o.OrganizationID = organizationID

	for _, idStr := range strings.Split(o.ResponsibleCategoriesStr, ",") {
		id, err := strconv.Atoi(strings.TrimSpace(idStr))
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest,
				"failed to parse category ID: "+err.Error())
		}
		o.ResponsibleCategories = append(o.ResponsibleCategories, id)
	}

	err = o.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate owner: "+err.Error())
	}

	_, err = s.storage.AddOperator(o)
	if err != nil {
		return errors.New("failed to add owner to storage: " + err.Error())
	}

	return c.Redirect(http.StatusFound, "/organization/operators")
}

func (s *Server) postOrganizationSetOperator(c echo.Context) error {
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
			"failed to bind owner: "+err.Error())
	}

	o.OrganizationID = organizationID

	for _, idStr := range strings.Split(o.ResponsibleCategoriesStr, ",") {
		id, err := strconv.Atoi(strings.TrimSpace(idStr))
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest,
				"failed to parse category ID: "+err.Error())
		}
		o.ResponsibleCategories = append(o.ResponsibleCategories, id)
	}

	err = o.Validate()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to validate owner: "+err.Error())
	}

	_, err = s.storage.SetOperator(o)
	if err != nil {
		return errors.New("failed to set owner in storage: " + err.Error())
	}

	return c.Redirect(http.StatusFound, "/organization/operators")
}

func (s *Server) postOrganizationRemoveOperator(c echo.Context) error {
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
			"failed to bind category: "+err.Error())
	}

	err = s.storage.RemoveOrganizationOperator(organizationID, o.ID)
	if err != nil {
		return errors.New("failed to remove category from storage: " +
			err.Error())
	}

	return c.Redirect(http.StatusFound, "/organization/operators")
}

func (s *Server) getOperator(c echo.Context) error {
	return c.Redirect(http.StatusFound, "/operator/requests")
}

// language=html
const operatorRequestsPage = `<!DOCTYPE html>
<html>
<head>
	<title>ЖКХ Пульс / Оператор / Обращения</title>
</head>
<body>
	<h1>ЖКХ Пульс / Оператор / Обращения</h1>
	<h2>{{.Login}}</h2>
	<a href="/logout">Выход</a>
	<hr/>
	{{range .Requests}}
		<p><b>{{.ID}}</b>, <b>Статус: {{.Status}}</b>, Дата и время: {{.CreatedAt.Format "2006-01-02 15:04"}}</p>
		<p><b>Владелец:</b> Имя: {{.OwnerName}}, Телефон: {{.OwnerPhone}}
			Адрес: {{.OwnerAddress}}</p>
		<p>{{.Text}}</p>
		{{if .HasNewStatus}}
			<form method="POST" action="/operator/set-request-in-progress">
				<input type="hidden" name="id" value="{{.ID}}"/>
				<button type="submit">Начать обработку</button>
			</form>
		{{else if .HasInProgressStatus}}
			<form method="POST" action="/operator/set-request-final">
				<input type="hidden" name="id" value="{{.ID}}"/>
				<select name="status" required>
					<option value="resolved">Разрешён</option>
					<option value="rejected">Отклонён</option>
					<option value="irrelevant">Не релевантен</option>
				</select>
				<textarea name="response"></textarea>
				<button type="submit">Завершить обработку</button>
			</form>
		{{else if .Response}}
			<p>{{.Response}}</p>
		{{end}}
		<hr/>
	{{end}}
</body>
</html>`

func (s *Server) getOperatorRequests(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	login, ok := sess.Values["login"].(string)
	if !ok {
		return errors.New("failed to get login from session")
	}

	operatorID, ok := sess.Values["operator_id"].(int)
	if !ok {
		return errors.New("failed to get operator ID from session")
	}

	rs, err := s.storage.OperatorRequests(operatorID)
	if err != nil {
		return errors.New("failed to get operator requests from storage: " + err.Error())
	}

	return c.Render(http.StatusOK, "operator_requests", echo.Map{
		"Login":    login,
		"Requests": rs,
	})
}

func (s *Server) postSetRequestInProgress(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	operatorID, ok := sess.Values["operator_id"].(int)
	if !ok {
		return errors.New("failed to get operator ID from session")
	}

	var newReq entity.Request

	err = c.Bind(&newReq)
	if err != nil {
		return errors.New("failed bind request: " + err.Error())
	}

	req, err := s.storage.OperatorRequest(operatorID, newReq.ID)
	if err != nil {
		return errors.New("failed to get operator request from storage: " +
			err.Error())
	}

	if req.Status != status.New {
		return echo.NewHTTPError(http.StatusBadRequest,
			"request status is not in new state")
	}

	req.Status = status.InProgress

	_, err = s.storage.SetOperatorRequest(operatorID, req)
	if err != nil {
		return errors.New("failed to set operator request: " + err.Error())
	}

	return c.Redirect(http.StatusFound, "/operator/requests")
}

func (s *Server) postSetRequestFinal(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	operatorID, ok := sess.Values["operator_id"].(int)
	if !ok {
		return errors.New("failed to get operator ID from session")
	}

	var newReq entity.Request

	err = c.Bind(&newReq)
	if err != nil {
		return errors.New("failed bind request: " + err.Error())
	}

	if !status.Final(newReq.Status) {
		return echo.NewHTTPError(http.StatusBadRequest,
			"status set is not final")
	}

	req, err := s.storage.OperatorRequest(operatorID, newReq.ID)
	if err != nil {
		return errors.New("failed to get operator request from storage: " +
			err.Error())
	}

	if status.Final(req.Status) {
		return echo.NewHTTPError(http.StatusBadRequest,
			"request status is already in final state")
	}

	req.Status = newReq.Status
	req.Response = newReq.Response

	_, err = s.storage.SetOperatorRequest(operatorID, req)
	if err != nil {
		return errors.New("failed to set operator request: " + err.Error())
	}

	return c.Redirect(http.StatusFound, "/operator/requests")
}

func (s *Server) getOwner(c echo.Context) error {
	return c.Redirect(http.StatusFound, "/owner/requests")
}

// language=html
const ownerRequestsPage = `<!DOCTYPE html>
<html>
<head>
	<title>ЖКХ Пульс / Владелец / Обращения</title>
</head>
<body>
	<h1>ЖКХ Пульс / Владелец / Обращения</h1>
	<h2>{{.Login}}</h2>
	<a href="/logout">Выход</a>
	<hr/>
	<form method="post" action="/owner/create-request">
		<textarea name="text" placeholder="Текст обращения"></textarea>
		<button type="submit">Отправить</button>
	</form>
	{{range .Requests}}
		<hr/>
		<p><b>{{.ID}}</b> , <b>Статус: {{.Status}}</b>, Дата и время: {{.CreatedAt.Format "2006-01-02 15:04"}}</p>
		{{if .CategoryName}}
			<p>Категория: {{.CategoryName}}</p>
		{{end}}
		<p>{{.Text}}</p>
		{{if .Response}}
			<p>{{.Response}}</p>
		{{end}}
	{{end}}
</body>
</html>`

func (s *Server) getOwnerRequests(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			"failed to get session")
	}

	login, ok := sess.Values["login"].(string)
	if !ok {
		return errors.New("failed to get login from session")
	}

	ownerID, ok := sess.Values["owner_id"].(int)
	if !ok {
		return errors.New("failed to get owner ID from session")
	}

	rs, err := s.storage.OwnerRequests(ownerID)
	if err != nil {
		return errors.New("failed to get owner requests from storage: " +
			err.Error())
	}

	return c.Render(http.StatusOK, "owner_requests", echo.Map{
		"Login":    login,
		"Requests": rs,
	})
}

func (s *Server) postOwnerCreateRequest(c echo.Context) error {
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

	text := c.FormValue("text")

	r := entity.Request{
		OrganizationID: organizationID,
		OwnerID:        ownerID,
		Text:           text,
		Status:         status.New,
		CreatedAt:      time.Now(),
	}

	categoryID, err := s.classifier.Classify(text)
	if err != nil {
		s.log.WithError(err).Error("failed to classify request text")
	} else {
		r.CategoryID = &categoryID

		o, err := s.storage.FindOrganizationOperator(
			organizationID, categoryID)
		if err != nil {
			s.log.WithError(err).Error(
				"failed to get request operator ID")
		} else {
			r.OperatorID = &o.ID
		}
	}

	_, err = s.storage.AddRequest(r)
	if err != nil {
		return errors.New("failed to add request to storage: " + err.Error())
	}

	return c.Redirect(http.StatusFound, "/owner/requests")
}
