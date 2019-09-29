package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/middleware"
	"github.com/sirupsen/logrus"

	"github.com/dimuls/swan/entity"
	"github.com/dimuls/swan/entity/role"
)

type Storage interface {
	PasswordCode(role string, login string) (entity.PasswordCode, error)
	RemovePasswordCode(role string, login string) error
	UpsertPasswordCode(entity.PasswordCode) error

	Admin(email string) (entity.Admin, error)
	SetAdminPasswordHash(adminID int, passwordHash []byte) error

	Categories() ([]entity.Category, error)
	AddCategory(entity.Category) (entity.Category, error)
	SetCategory(entity.Category) (entity.Category, error)
	RemoveCategory(categoryID int) error

	CategorySamples() ([]entity.CategorySample, error)
	SetCategorySamples([]entity.CategorySample) error

	Organization(email string) (entity.Organization, error)
	Organizations() ([]entity.Organization, error)
	AddOrganization(entity.Organization) (entity.Organization, error)
	SetOrganization(entity.Organization) (entity.Organization, error)
	RemoveOrganization(organizationID int) error
	SetOrganizationPasswordHash(organizationID int, passwordHash []byte) error

	Operator(phone string) (entity.Operator, error)
	OrganizationOperators(organizationID int) ([]entity.Operator, error)
	AddOperator(entity.Operator) (entity.Operator, error)
	SetOperator(entity.Operator) (entity.Operator, error)
	RemoveOrganizationOperator(organizationID int, operatorID int) error
	FindOrganizationOperator(organizationID int, categoryID int) (
		entity.Operator, error)
	SetOperatorPasswordHash(operatorID int, passwordHash []byte) error

	Owner(phone string) (entity.Owner, error)
	OrganizationOwners(organizationID int) ([]entity.Owner, error)
	AddOwner(entity.Owner) (entity.Owner, error)
	SetOwner(entity.Owner) (entity.Owner, error)
	RemoveOrganizationOwner(organizationID int, ownerID int) error
	SetOwnerPasswordHash(ownerID int, passwordHash []byte) error

	OperatorRequest(operatorID int, requestID int) (entity.Request, error)
	OperatorRequests(operatorID int) ([]entity.RequestExtended, error)
	SetOperatorRequest(operatorID int, r entity.Request) (entity.Request, error)

	OwnerRequests(ownerID int) ([]entity.RequestExtended, error)
	AddRequest(entity.Request) (entity.Request, error)
}

type Classifier interface {
	Train(samples []entity.CategorySample) error
	Training() (bool, error)
	Classify(text string) (int, error)
}

type SMSSender interface {
	SendSMS(phone string, msg string) error
}

type EmailSender interface {
	SendEmail(email string, msg string) error
}

type Server struct {
	bindAddr    string
	debug       bool
	storage     Storage
	smsSender   SMSSender
	emailSender EmailSender
	classifier  Classifier

	echo *echo.Echo

	waitGroup sync.WaitGroup

	log *logrus.Entry
}

func NewServer(bindAddr string, s Storage, ss SMSSender, es EmailSender,
	c Classifier, debug bool) *Server {

	return &Server{
		bindAddr:    bindAddr,
		debug:       debug,
		storage:     s,
		smsSender:   ss,
		emailSender: es,
		classifier:  c,

		log: logrus.WithField("subsystem", "web_server"),
	}
}

func (s *Server) Start() error {
	e := echo.New()

	e.Debug = s.debug

	e.HideBanner = true
	e.HidePort = true

	var err error

	e.Renderer, err = initRenderer(map[string]string{
		"login":                  loginPage,
		"register":               registerPage,
		"password":               passwordPage,
		"admin_organizations":    adminOrganizationsPage,
		"admin_classifier":       adminClassifierPage,
		"organization_owners":    organizationOwnersPage,
		"organization_operators": organizationOperatorsPage,
		"operator_requests":      operatorRequestsPage,
		"owner_requests":         ownerRequestsPage,
	})
	if err != nil {
		return errors.New("failed to init renderer: " + err.Error())
	}

	e.Use(middleware.Recover())
	e.Use(logrusLogger)
	e.Use(session.Middleware(sessions.NewCookieStore(
		[]byte("secret")))) // TODO: move secrets to environment variable
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost", "http://localhost:3000"},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders: []string{"Cookie"},
	}))

	e.HTTPErrorHandler = func(err error, c echo.Context) {
		var (
			code = http.StatusInternalServerError
			msg  interface{}
		)

		if he, ok := err.(*echo.HTTPError); ok {
			code = he.Code
			msg = he.Message
		} else if e.Debug {
			msg = err.Error()
		} else {
			msg = http.StatusText(code)
		}
		if _, ok := msg.(string); !ok {
			msg = fmt.Sprintf("%v", msg)
		}

		// Send response
		if !c.Response().Committed {
			if c.Request().Method == http.MethodHead { // Issue #608
				err = c.NoContent(code)
			} else {
				err = c.String(code, msg.(string))
			}
			if err != nil {
				s.log.WithError(err).Error("failed to error response")
			}
		}
	}

	// Statis pages

	e.GET("", s.getIndex)

	e.GET("/login", s.getLogin)
	e.POST("/login", s.postLogin)

	e.GET("/logout", s.getLogout)

	e.GET("/register", s.getRegister)
	e.POST("/register", s.postRegister)

	e.GET("/password", s.getPassword)
	e.POST("/password", s.postPassword)

	admin := e.Group("/admin", forRoles(role.Admin))

	admin.GET("", s.getAdmin)

	admin.GET("/organizations", s.getAdminOrganizations)

	admin.POST("/create-organization", s.postAdminCreateOrganization)
	admin.POST("/set-organization", s.postAdminSetOrganization)
	admin.POST("/remove-organization", s.postAdminRemoveOrganization)

	admin.GET("/classifier", s.getAdminClassifier)
	admin.POST("/classifier/create-category", s.postAdminCreateCategory)
	admin.POST("/classifier/set-category", s.postAdminSetCategory)
	admin.POST("/classifier/remove-category", s.postAdminRemoveCategory)

	admin.POST("/classifier/train", s.postClassifierTrain)

	org := e.Group("/organization", forRoles(role.Organization))

	org.GET("", s.getOrganization)

	org.GET("/owners", s.getOrganizationOwners)
	org.POST("/create-owner", s.postOrganizationCreateOwner)
	org.POST("/set-owner", s.postOrganizationSetOwner)
	org.POST("/remove-owner", s.postOrganizationRemoveOwner)

	org.GET("/operators", s.getOrganizationOperators)
	org.POST("/create-operator", s.postOrganizationCreateOperator)
	org.POST("/set-operator", s.postOrganizationSetOperator)
	org.POST("/remove-operator", s.postOrganizationRemoveOperator)

	oper := e.Group("/operator", forRoles(role.Operator))

	oper.GET("", s.getOperator)

	oper.GET("/requests", s.getOperatorRequests)
	oper.POST("/set-request-in-progress", s.postSetRequestInProgress)
	oper.POST("/set-request-final", s.postSetRequestFinal)

	own := e.Group("/owner", forRoles(role.Owner))

	own.GET("", s.getOwner)

	own.GET("/requests", s.getOwnerRequests)
	own.POST("/create-request", s.postOwnerCreateRequest)

	// API

	api := e.Group("/api")

	api.POST("/login", s.postAPILogin)

	api.POST("/password-code", s.postAPIPasswordCode)
	api.POST("/password", s.postAPIPassword)

	api.GET("/entity", s.getAPIEntity, forRoles(role.Admin, role.Organization,
		role.Operator, role.Owner))

	api.GET("/categories", s.getAPICategories,
		forRoles(role.Organization, role.Operator))

	categories := api.Group("/categories",
		forRoles(role.Admin))
	categories.POST("", s.postAPICategories)
	categories.PUT("/:category_id", s.putAPICategory)
	categories.DELETE("/:category_id", s.deleteAPICategory)

	categorySamples := api.Group("/category-samples",
		forRoles(role.Admin))
	categorySamples.POST("", s.postAPICategorySamples)
	categorySamples.POST("/classifier", s.postAPICategorySamplesClassifier)
	categorySamples.GET("/classifier/training",
		s.getAPICategorySamplesClassifierTraining)

	organizations := api.Group("/organizations", forRoles(role.Admin))
	organizations.GET("", s.getAPIOrganizations)
	organizations.POST("", s.postAPIOrganizations)
	organizations.PUT("/:organization_id", s.putAPIOrganization)
	organizations.DELETE("/:organization_id", s.deleteAPIOrganization)

	operators := api.Group("/operators", forRoles(role.Organization))
	operators.GET("", s.getAPIOperators)
	operators.POST("", s.postAPIOperators)
	operators.PUT("/:operator_id", s.putAPIOperator)
	operators.DELETE("/:operator_id", s.deleteAPIOperator)

	owners := api.Group("/owners", forRoles(role.Organization))
	owners.GET("", s.getAPIOwners)
	owners.POST("", s.postAPIOwners)
	owners.PUT("/:owner_id", s.putAPIOwner)
	owners.DELETE("/:owner_id", s.deleteAPIOwner)

	operatorRequests := api.Group("/operators/requests",
		forRoles(role.Operator))
	operatorRequests.GET("", s.getAPIOperatorsRequests)
	operatorRequests.PUT("/:request_id", s.putAPIOperatorsRequest)

	ownerRequests := api.Group("/owners/requests",
		forRoles(role.Owner))
	ownerRequests.GET("", s.getAPIOwnersRequests)
	ownerRequests.POST("", s.postAPIOwnersRequests)

	s.echo = e

	s.waitGroup.Add(1)
	go func() {
		defer s.waitGroup.Done()
		err := e.Start(s.bindAddr)
		if err != nil && err != http.ErrServerClosed {
			s.log.WithError(err).Error("failed to start")
		}
	}()

	return nil
}

func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	err := s.echo.Shutdown(ctx)
	if err != nil {
		s.log.WithError(err).Error("failed to graceful stop")
	}

	s.waitGroup.Wait()
}

func forRoles(wantRoles ...string) func(echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if len(wantRoles) == 0 {
				return errors.New("wanted roles are empty")
			}

			sess, err := session.Get("session", c)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest,
					"failed to get session")
			}

			roleI, exists := sess.Values["role"]
			if !exists {
				return echo.NewHTTPError(http.StatusForbidden)
			}

			gotRole, ok := roleI.(string)
			if !ok {
				return echo.NewHTTPError(http.StatusBadRequest,
					"failed to get role from session")
			}

			for _, wantRole := range wantRoles {
				if gotRole == wantRole {
					return next(c)
				}
			}

			return echo.NewHTTPError(http.StatusForbidden)
		}
	}
}

func logrusLogger(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()

		err := next(c)

		stop := time.Now()

		if err != nil {
			c.Error(err)
		}

		req := c.Request()
		res := c.Response()

		p := req.URL.Path
		if p == "" {
			p = ""
		}

		bytesIn := req.Header.Get(echo.HeaderContentLength)
		if bytesIn == "" {
			bytesIn = "0"
		}

		entry := logrus.WithFields(map[string]interface{}{
			"subsystem":    "web_server",
			"remote_ip":    c.RealIP(),
			"host":         req.Host,
			"query_params": c.QueryParams(),
			"uri":          req.RequestURI,
			"method":       req.Method,
			"path":         p,
			"referer":      req.Referer(),
			"user_agent":   req.UserAgent(),
			"status":       res.Status,
			"latency":      stop.Sub(start).String(),
			"bytes_in":     bytesIn,
			"bytes_out":    strconv.FormatInt(res.Size, 10),
		})

		const msg = "request handled"

		if res.Status >= 500 {
			if err != nil {
				entry = entry.WithError(err)
			}
			entry.Error(msg)
		} else if res.Status >= 400 {
			entry.Warn(msg)
		} else {
			entry.Info(msg)
		}

		return nil
	}
}
