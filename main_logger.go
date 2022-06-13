package main

import (
	"github.com/rond-authz/rond/internal/config"

	"github.com/sirupsen/logrus"
)

type failLogger struct {
	log *logrus.Logger
	env config.EnvironmentVariables
}

func (failLogger failLogger) opaModulesLoad(err error) {
	failLogger.log.WithFields(logrus.Fields{
		"error":        logrus.Fields{"message": err.Error()},
		"opaDirectory": failLogger.env.OPAModulesDirectory,
	}).Errorf("load OPA modules failed")
}

func (failLogger failLogger) regoFileRead(err error) {
	failLogger.log.WithFields(logrus.Fields{
		"error":        logrus.Fields{"message": err.Error()},
		"opaDirectory": failLogger.env.OPAModulesDirectory,
	}).Errorf("failed rego file read")
}

func (failLogger failLogger) loadOas(err error) {
	failLogger.log.WithFields(logrus.Fields{
		"error": logrus.Fields{"message": err.Error()},
	}).Errorf("failed to load oas")
}

func (failLogger failLogger) mongoInit(err error) {
	failLogger.log.WithFields(logrus.Fields{
		"error": logrus.Fields{"message": err.Error()},
	}).Errorf("error during init of mongo collection")
}

func (failLogger failLogger) createEvaluators(err error) {
	failLogger.log.WithFields(logrus.Fields{
		"error": logrus.Fields{"message": err.Error()},
	}).Errorf("failed to create evaluators")
}

func (failLogger failLogger) routerSetup(err error) {
	failLogger.log.WithFields(logrus.Fields{
		"error": logrus.Fields{"message": err.Error()},
	}).Errorf("failed router setup")
}
