/*
 * Copyright 2019 Mia srl
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rbac-service/helpers"

	"github.com/gorilla/mux"
	"github.com/mia-platform/configlib"
	"github.com/mia-platform/glogger"
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

	documentationURL := fmt.Sprintf("%s://%s%s", HTTPScheme, env.TargetServiceHost, env.TargetServiceOASPath)
	var oas *OpenAPISpec
	for {
		oas, err = fetchOpenAPI(documentationURL)
		if err != nil {
			log.WithFields(logrus.Fields{
				"targetServiceHost": env.TargetServiceHost,
				"targetOASPath":     env.TargetServiceOASPath,
			}).Warnf("failed OAS fetch: %s", err.Error())
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}

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
