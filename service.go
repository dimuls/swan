package swan

import (
	"errors"

	"github.com/dimuls/swan/classifier"
	"github.com/dimuls/swan/postgres"
	"github.com/dimuls/swan/web"
)

type Service struct {
	webServer *web.Server
}

func NewService(
	postgresStorageURI string,
	classifierAPIURI string,
	webServerBindAddr string,
	webServerDebug bool,
) (*Service, error) {

	s, err := postgres.NewStorage(postgresStorageURI)
	if err != nil {
		return nil, errors.New("failed to create postgres storage: " +
			err.Error())
	}

	err = s.Migrate()
	if err != nil {
		return nil, errors.New("failed to migrate postgres storage: " +
			err.Error())
	}

	c := classifier.NewClient(classifierAPIURI)

	// TODO: implement sms and email senders
	ds := dummySender{}

	ws := web.NewServer(webServerBindAddr, s, ds, ds, c, webServerDebug)

	return &Service{
		webServer: ws,
	}, nil
}

func (s *Service) Start() {
	s.webServer.Start()
}

func (s *Service) Stop() {
	s.webServer.Stop()
}

type dummySender struct{}

func (dummySender) SendSMS(phone string, text string) error {
	return nil
}

func (dummySender) SendEmail(email string, text string) error {
	return nil
}
