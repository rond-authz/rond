// Copyright 2021 Mia srl
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	swagger "github.com/davidebianchi/gswagger"
	"github.com/davidebianchi/gswagger/apirouter"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rond-authz/rond/helpers"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/internal/mongoclient"

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

	oas, err := loadOASFromFileOrNetwork(log, env)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error":       logrus.Fields{"message": err.Error()},
			"oasFilePath": env.APIPermissionsFilePath,
			"oasApiPath":  env.TargetServiceOASPath,
		}).Errorf("failed to load oas")
		return
	}
	log.WithFields(logrus.Fields{
		"oasFilePath": env.APIPermissionsFilePath,
		"oasApiPath":  env.TargetServiceOASPath,
	}).Trace("OAS successfully loaded")

	mongoClient, err := mongoclient.NewMongoClient(env, log)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": logrus.Fields{"message": err.Error()},
		}).Errorf("MongoDB setup failed")
		return
	}

	ctx := glogger.WithLogger(
		mongoclient.WithMongoClient(context.Background(), mongoClient),
		logrus.NewEntry(log),
	)

	policiesEvaluators, err := setupEvaluators(ctx, mongoClient, oas, opaModuleConfig, env)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": logrus.Fields{"message": err.Error()},
		}).Errorf("failed to create evaluators")
		return
	}
	log.WithField("policiesLength", len(policiesEvaluators)).Debug("policies evaluators partial results computed")

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
		Addr:              fmt.Sprintf("0.0.0.0:%s", env.HTTPPort),
		Handler:           router,
		ReadHeaderTimeout: time.Second,
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
	router := mux.NewRouter().UseEncodedPath()
	router.Use(glogger.RequestMiddlewareLogger(log, []string{"/-/"}))
	serviceName := "rönd"
	StatusRoutes(router, serviceName, env.ServiceVersion)

	registry := prometheus.NewRegistry()
	m := metrics.SetupMetrics("rond")
	if env.ExposeMetrics {
		m.MustRegister(registry)
		metrics.MetricsRoute(router, registry)
	}
	router.Use(metrics.RequestMiddleware(m))

	router.Use(config.RequestMiddlewareEnvironments(env))

	evalRouter := router.NewRoute().Subrouter()
	if env.Standalone {
		router.Use(helpers.AddHeadersToProxyMiddleware(log, env.GetAdditionalHeadersToProxy()))
		swaggerRouter, err := swagger.NewRouter(apirouter.NewGorillaMuxRouter(router), swagger.Options{
			Context: context.Background(),
			Openapi: &openapi3.T{
				Info: &openapi3.Info{
					Title:   serviceName,
					Version: env.ServiceVersion,
				},
			},
			JSONDocumentationPath: "/openapi/json",
			YAMLDocumentationPath: "/openapi/yaml",
		})
		if err != nil {
			return nil, err
		}
		if err := addStandaloneRoutes(swaggerRouter); err != nil {
			return nil, err
		}

		if err = swaggerRouter.GenerateAndExposeSwagger(); err != nil {
			return nil, err
		}
	}

	evalRouter.Use(OPAMiddleware(opaModuleConfig, oas, &env, policiesEvaluators))

	if mongoClient != nil {
		evalRouter.Use(mongoclient.MongoClientInjectorMiddleware(mongoClient))
	}

	setupRoutes(evalRouter, oas, env)

	//#nosec G104 -- Produces a false positive
	router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		log.Tracef("Registered path: %s", path)
		return nil
	})

	return router, nil
}
