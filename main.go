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

	"rbac-service/helpers"

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
	var env EnvironmentVariables
	err := configlib.GetEnvVariables(envVariablesConfig, &env)
	if err != nil {
		panic(err.Error())
	}

	// Init logger instance.
	log, err := glogger.InitHelper(glogger.InitOptions{Level: env.LogLevel})
	if err != nil {
		panic(err.Error())
	}

	// Routing
	router := mux.NewRouter()
	router.Use(glogger.RequestMiddlewareLogger(log, []string{"/-/"}))
	StatusRoutes(router, "rbac-service", env.ServiceVersion)

	router.Use(RequestMiddlewareEnvironments(env))

	// Load OPA module file.
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

	router.Use(OPAMiddleware(opaModuleConfig, oas))

	setupRoutes(router, oas)

	router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		log.Infof("Registered path: %s", path)
		return nil
	})

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
