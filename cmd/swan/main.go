package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/dimuls/swan"
)

func main() {
	service, err := swan.NewService(
		os.Getenv("POSTGRES_STORAGE_URI"),
		os.Getenv("CLASSIFIER_API_URI"),
		os.Getenv("WEB_SERVER_BIND_ADDR"),
		os.Getenv("WEB_SERVER_DEBUG") == "1")
	if err != nil {
		logrus.WithError(err).Fatal("failed to create swan service")
	}

	service.Start()

	ss := make(chan os.Signal)
	signal.Notify(ss, os.Interrupt, syscall.SIGTERM)

	s := <-ss

	logrus.Infof("captured %v signal, stopping", s)

	startTime := time.Now()

	service.Stop()

	endTime := time.Now()

	logrus.Infof("stopped in %g seconds, exiting",
		endTime.Sub(startTime).Seconds())
}
