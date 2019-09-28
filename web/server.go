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

	OperatorRequests(operatorID int) ([]entity.Request, error)
	SetOperatorRequest(operatorID int, r entity.Request) (entity.Request, error)

	OwnerRequests(ownerID int) ([]entity.Request, error)
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

func (s *Server) Start() {
	e := echo.New()

	e.Debug = s.debug

	e.HideBanner = true
	e.HidePort = true

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

	e.POST("/login", s.postLogin)

	e.POST("/password-code", s.postPasswordCode)
	e.POST("/password", s.postPassword)

	e.GET("/categories", s.getCategories,
		forRoles(role.Organization, role.Operator))

	categories := e.Group("/categories",
		forRoles(role.Admin))
	categories.POST("/", s.postCategories)
	categories.PUT("/:category_id", s.putCategory)
	categories.DELETE("/:category_id", s.deleteCategory)

	categorySamples := e.Group("/category-samples",
		forRoles(role.Admin))
	categorySamples.POST("/", s.postCategorySamples)
	categorySamples.POST("/classifier", s.postCategorySamplesClassifier)
	categorySamples.GET("/classifier/training",
		s.getCategorySamplesClassifierTraining)

	organizations := e.Group("/organizations", forRoles(role.Admin))
	organizations.GET("/", s.getOrganizations)
	organizations.POST("/", s.postOrganizations)
	organizations.PUT("/:organization_id", s.putOrganization)
	organizations.DELETE("/:organization_id", s.deleteOrganization)

	operators := e.Group("/operators", forRoles(role.Organization))
	operators.GET("/", s.getOperators)
	operators.POST("/", s.postOperators)
	operators.PUT("/:operator_id", s.putOperator)
	operators.DELETE("/:operator_id", s.deleteOperator)

	owners := e.Group("/owners", forRoles(role.Organization))
	owners.GET("/", s.getOwners)
	owners.POST("/", s.postOwners)
	owners.PUT("/:owner_id", s.putOwner)
	owners.DELETE("/:owner_id", s.deleteOwner)

	operatorRequests := e.Group("/operators/requests",
		forRoles(role.Operator))
	operatorRequests.GET("/", s.getOperatorsRequests)
	operatorRequests.PUT("/:request_id", s.putOperatorsRequest)

	ownerRequests := e.Group("/owners/requests",
		forRoles(role.Owner))
	ownerRequests.GET("/", s.getOwnersRequests)
	ownerRequests.POST("/", s.postOwnersRequests)

	s.echo = e

	s.waitGroup.Add(1)
	go func() {
		defer s.waitGroup.Done()
		err := e.Start(s.bindAddr)
		if err != nil && err != http.ErrServerClosed {
			s.log.WithError(err).Error("failed to start")
		}
	}()
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
			p = "/"
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
