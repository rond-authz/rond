/*
 * Copyright © 2021-present Mia s.r.l.
 * All rights reserved
 */

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"git.tools.mia-platform.eu/platform/core/rbac-service/helpers"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/mongoclient"

	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
)

const HTTPScheme = "http"

func main() {
	entrypoint(make(chan os.Signal, 1))
	os.Exit(0)
}

func entrypoint(shutdown chan os.Signal) {
	env := config.GetEnvOrDie()

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
	log.WithField("opaModuleFileName", opaModuleConfig.Name).Trace("rego module successfully loaded")

	oas, err := loadOAS(log, env)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": logrus.Fields{"message": err.Error()},
		}).Errorf("failed to load oas")
		return
	}
	log.WithField("oasAPIPermissionsFilePath", env.APIPermissionsFilePath).Trace("OAS successfully loaded")

	mongoClient, err := mongoclient.NewMongoClient(env, log)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": logrus.Fields{"message": err.Error()},
		}).Errorf("error during init of mongo collection")
		return
	}
	log.Trace("MongoDB client set up completed")

	ctx := glogger.WithLogger(mongoclient.WithMongoClient(context.Background(), mongoClient), logrus.NewEntry(log))

	policiesEvaluators, err := setupEvaluators(ctx, mongoClient, oas, opaModuleConfig, env)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": logrus.Fields{"message": err.Error()},
		}).Errorf("failed to create evaluators")
		return
	}
	log.WithField("policiesLength", len(policiesEvaluators)).Trace("policies evaluators partial results computed")

	// Routing
	router, err := setupRouter(log, env, opaModuleConfig, oas, policiesEvaluators, mongoClient)
	if mongoClient != nil {
		defer mongoClient.Disconnect()
	}
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": logrus.Fields{"message": err.Error()},
		}).Errorf("failed router setup")
		return
	}
	log.Trace("router setup completed")

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

func setupRouter(
	log *logrus.Logger,
	env config.EnvironmentVariables,
	opaModuleConfig *OPAModuleConfig,
	oas *OpenAPISpec,
	policiesEvaluators PartialResultsEvaluators,
	mongoClient *mongoclient.MongoClient,
) (*mux.Router, error) {
	router := mux.NewRouter()
	router.Use(glogger.RequestMiddlewareLogger(log, []string{"/-/"}))
	StatusRoutes(router, "rbac-service", env.ServiceVersion)

	router.Use(config.RequestMiddlewareEnvironments(env))

	evalRouter := router.NewRoute().Subrouter()
	if env.Standalone {
		addStandaloneRoutes(router)
	}

	evalRouter.Use(OPAMiddleware(opaModuleConfig, oas, &env, policiesEvaluators))

	if mongoClient != nil {
		evalRouter.Use(mongoclient.MongoClientInjectorMiddleware(mongoClient))
	}

	setupRoutes(evalRouter, oas, env)

	router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		log.Tracef("Registered path: %s", path)
		return nil
	})

	return router, nil
}
