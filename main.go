/*
 * Copyright © 2021-present Mia s.r.l.
 * All rights reserved
 */

package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"git.tools.mia-platform.eu/platform/core/rbac-service/helpers"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/mongoclient"

	"github.com/gorilla/mux"
	"github.com/mia-platform/configlib"
	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
)

const HTTPScheme = "http"

func main() {
	entrypoint(make(chan os.Signal, 1))
	os.Exit(0)
}

func entrypoint(shutdown chan os.Signal) {
	var env config.EnvironmentVariables
	err := configlib.GetEnvVariables(config.EnvVariablesConfig, &env)
	if err != nil {
		panic(err.Error())
	}

	// Init logger instance.
	log, err := glogger.InitHelper(glogger.InitOptions{Level: env.LogLevel})
	if err != nil {
		panic(err.Error())
	}

	if _, err := os.Stat(env.OPAModulesDirectory); err != nil {
		log.WithFields(logrus.Fields{
			"error":        logrus.Fields{"message": err.Error()},
			"opaDirectory": env.OPAModulesDirectory,
		}).Errorf("load OPA modules failed")
		return
	}

	opaModuleConfig, err := loadRegoModule(env.OPAModulesDirectory)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error":        logrus.Fields{"message": err.Error()},
			"opaDirectory": env.OPAModulesDirectory,
		}).Errorf("failed rego file read")
		return
	}

	oas, err := loadOAS(log, env)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": logrus.Fields{"message": err.Error()},
		}).Errorf("failed to load oas")
		return
	}

	// Routing
	router, mongoClient, err := setupRouter(log, env, opaModuleConfig, oas)
	if mongoClient != nil {
		defer mongoClient.Disconnect()
	}
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": logrus.Fields{"message": err.Error()},
		}).Errorf("failed router setup")
		return
	}

	srv := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%s", env.HTTPPort),
		Handler: router,
	}

	go func() {
		log.WithField("port", env.HTTPPort).Info("Starting server")
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	// sigterm signal sent from kubernetes
	signal.Notify(shutdown, syscall.SIGTERM)
	// We'll accept graceful shutdowns when quit via  and SIGTERM (Ctrl+/)
	// SIGINT (Ctrl+C), SIGKILL or SIGQUIT will not be caught.
	helpers.GracefulShutdown(srv, shutdown, log, env.DelayShutdownSeconds)
}

func setupRouter(log *logrus.Logger, env config.EnvironmentVariables, opaModuleConfig *OPAModuleConfig, oas *OpenAPISpec) (*mux.Router, *mongoclient.MongoClient, error) {
	router := mux.NewRouter()
	router.Use(glogger.RequestMiddlewareLogger(log, []string{"/-/"}))
	StatusRoutes(router, "rbac-service", env.ServiceVersion)

	router.Use(config.RequestMiddlewareEnvironments(env))
	router.Use(OPAMiddleware(opaModuleConfig, oas, &env))

	mongoClient, err := mongoclient.NewMongoClient(env, log)

	if err != nil {
		return nil, nil, fmt.Errorf("error during init of mongo collection: %s", err.Error())
	}
	if mongoClient != nil {
		router.Use(mongoclient.MongoClientInjectorMiddleware(mongoClient))
	}

	setupRoutes(router, oas, env)

	router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		log.Infof("Registered path: %s", path)
		return nil
	})

	return router, mongoClient, nil
}
