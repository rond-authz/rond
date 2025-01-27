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

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/custom_builtins"
	"github.com/rond-authz/rond/internal/audit"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/helpers"
	"github.com/rond-authz/rond/internal/mongoclient"
	"github.com/rond-authz/rond/logging"
	rondlogrus "github.com/rond-authz/rond/logging/logrus"
	"github.com/rond-authz/rond/metrics"
	rondprometheus "github.com/rond-authz/rond/metrics/prometheus"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/sdk"
	"github.com/rond-authz/rond/sdk/inputuser"
	inputusermongoclient "github.com/rond-authz/rond/sdk/inputuser/mongo"
	"github.com/rond-authz/rond/service"
	"github.com/rond-authz/rond/types"

	"github.com/gorilla/mux"
	glogrus "github.com/mia-platform/glogger/v4/loggers/logrus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/sirupsen/logrus"
)

func main() {
	env := config.GetEnvOrDie()

	entrypoint(make(chan os.Signal, 1), env)
	os.Exit(0)
}

func entrypoint(shutdown chan os.Signal, env config.EnvironmentVariables) {
	// Init logger instance.
	log, err := glogrus.InitHelper(glogrus.InitOptions{Level: env.LogLevel})
	if err != nil {
		panic(err.Error())
	}

	app, err := setupService(env, log)
	if err != nil {
		panic(err.Error())
	}
	defer app.close()

	srv := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%s", env.HTTPPort),
		Handler:           app.router,
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

type app struct {
	router       *mux.Router
	sdkBootState *service.SDKBootState

	closeFn []func()
}

func (a *app) close() {
	for _, fn := range a.closeFn {
		fn()
	}
}

func setupService(env config.EnvironmentVariables, log *logrus.Logger) (*app, error) {
	var closeFn []func()
	if _, err := os.Stat(env.OPAModulesDirectory); err != nil {
		log.WithFields(logrus.Fields{
			"error":        logrus.Fields{"message": err.Error()},
			"opaDirectory": env.OPAModulesDirectory,
		}).Errorf("load OPA modules failed")
		return nil, err
	}

	opaModuleConfig, err := core.LoadRegoModule(env.OPAModulesDirectory)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error":        logrus.Fields{"message": err.Error()},
			"opaDirectory": env.OPAModulesDirectory,
		}).Errorf("failed rego file read")
		return nil, err
	}
	log.WithField("opaModuleFileName", opaModuleConfig.Modules[0].Name).Trace("rego module successfully loaded")

	rondLogger := rondlogrus.NewLogger(log)
	oas, err := openapi.LoadOASFromFileOrNetwork(rondLogger, openapi.LoadOptions{
		APIPermissionsFilePath: env.APIPermissionsFilePath,
		TargetServiceOASPath:   env.TargetServiceOASPath,
		TargetServiceHost:      env.TargetServiceHost,
	})
	if err != nil {
		log.WithFields(logrus.Fields{
			"error":       logrus.Fields{"message": err.Error()},
			"oasFilePath": env.APIPermissionsFilePath,
			"oasApiPath":  env.TargetServiceOASPath,
		}).Errorf("failed to load oas")
		return nil, err
	}
	log.WithFields(logrus.Fields{
		"oasFilePath": env.APIPermissionsFilePath,
		"oasApiPath":  env.TargetServiceOASPath,
	}).Trace("OAS successfully loaded")

	var mongoDriver types.MongoClient
	if env.MongoDBUrl != "" {
		client, err := mongoclient.NewMongoClient(rondLogger, env.MongoDBUrl, mongoclient.ConnectionOpts{
			MaxIdleTimeMs: env.MongoDBConnectionMaxIdleTimeMs,
		})
		if err != nil {
			log.WithFields(logrus.Fields{
				"error": logrus.Fields{"message": err.Error()},
			}).Errorf("MongoDB setup failed")
			return nil, err
		}
		closeFn = append(closeFn, func() {
			if err := client.Disconnect(); err != nil {
				log.WithFields(logrus.Fields{
					"error": logrus.Fields{"message": err.Error()},
				}).Errorf("MongoDB disconnection failed")
			}
		})
		mongoDriver = client
	}

	var mongoClientForAudits types.MongoClient
	if env.AuditStorageMongoDBURL != "" {
		// NOTE: if the audit connection string is the same as the main one, we reuse
		// the same connection preventing the creation of a new driver connection pool.
		if mongoDriver != nil {
			mongoClientForAudits = mongoDriver
		}

		if env.AuditStorageMongoDBURL != env.MongoDBUrl {
			client, err := mongoclient.NewMongoClient(rondLogger, env.AuditStorageMongoDBURL, mongoclient.ConnectionOpts{
				MaxIdleTimeMs: env.MongoDBConnectionMaxIdleTimeMs,
			})
			if err != nil {
				log.WithFields(logrus.Fields{
					"error": logrus.Fields{"message": err.Error()},
				}).Errorf("MongoDB setup for audit traces failed")
				return nil, err
			}
			closeFn = append(closeFn, func() {
				if err := client.Disconnect(); err != nil {
					log.WithFields(logrus.Fields{
						"error": logrus.Fields{"message": err.Error()},
					}).Errorf("MongoDB disconnection failed")
				}
			})
			mongoClientForAudits = client
		}
	}

	var mongoClientForUserBindings inputuser.Client
	var mongoClientForBuiltin custom_builtins.IMongoClient
	if mongoDriver != nil {
		client, err := inputusermongoclient.NewMongoClient(rondLogger, mongoDriver, inputusermongoclient.Config{
			RolesCollectionName:    env.RolesCollectionName,
			BindingsCollectionName: env.BindingsCollectionName,
		})
		if err != nil {
			log.WithFields(logrus.Fields{
				"error": logrus.Fields{"message": err.Error()},
			}).Errorf("MongoDB setup failed")
			return nil, err
		}
		mongoClientForUserBindings = client

		clientForBuiltin, err := custom_builtins.NewMongoClient(rondLogger, mongoDriver)
		if err != nil {
			log.WithFields(logrus.Fields{
				"error": logrus.Fields{"message": err.Error()},
			}).Errorf("MongoDB for builtin setup failed")
			return nil, err
		}
		mongoClientForBuiltin = clientForBuiltin
	}

	var m *metrics.Metrics
	var registry *prometheus.Registry
	if env.ExposeMetrics {
		registry = prometheus.NewRegistry()
		registry.MustRegister(
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		)
		m = rondprometheus.SetupMetrics(registry)
	}

	var auditConfig audit.Config
	if env.EnableAuditTrail && env.AuditConfigPath != "" {
		auditConfig, err = audit.LoadConfiguration(env.AuditConfigPath)
		if err != nil {
			log.WithFields(logrus.Fields{
				"error":           logrus.Fields{"message": err.Error()},
				"auditConfigPath": env.AuditConfigPath,
			}).Errorf("failed to load oas")
			return nil, err
		}
	}

	sdkBoot := service.NewSDKBootState()
	go func(sdkBoot *service.SDKBootState) {
		sdk := prepSDKOrDie(
			log,
			env,
			auditConfig,
			opaModuleConfig,
			oas,
			mongoClientForBuiltin,
			mongoClientForAudits,
			rondLogger,
			m,
		)
		sdkBoot.Ready(sdk)
	}(sdkBoot)

	// Routing
	log.Trace("router setup initialization")
	router, err := service.SetupRouter(log, env, opaModuleConfig, oas, sdkBoot, mongoClientForUserBindings, registry)
	if err != nil {
		return nil, err
	}
	log.Trace("router setup initialization done")

	return &app{
		router:       router,
		sdkBootState: sdkBoot,
		closeFn:      closeFn,
	}, nil
}

func prepSDKOrDie(
	log *logrus.Logger,
	env config.EnvironmentVariables,
	auditConfig audit.Config,
	opaModuleConfig *core.OPAModuleConfig,
	oas *openapi.OpenAPISpec,
	mongoClientForBuiltin custom_builtins.IMongoClient,
	mongoClientForAudits types.MongoClient,
	rondLogger logging.Logger,
	m *metrics.Metrics,
) sdk.OASEvaluatorFinder {
	auditLabels := make(sdk.AuditLabels)
	if env.AuditTargetServiceName != "" {
		auditLabels[audit.AuditAdditionalDataRequestTargetServiceKey] = env.AuditTargetServiceName
	}

	sdk, err := sdk.NewFromOAS(context.Background(), opaModuleConfig, oas, &sdk.Options{
		Metrics: m,
		EvaluatorOptions: &sdk.EvaluatorOptions{
			EnablePrintStatements: env.IsTraceLogLevel(),
			MongoClient:           mongoClientForBuiltin,
			EnableAuditTracing:    env.EnableAuditTrail,
			AuditTracingOptions: sdk.AuditEvaluatorOptions{
				MongoDBClient:       mongoClientForAudits,
				AuditCollectionName: env.AuditStorageMongoDBCollectionName,
				StorageMode:         env.AuditStorageMode,
				AuditConfig:         auditConfig,
			},
		},
		Logger:      rondLogger,
		AuditLabels: auditLabels,
	})
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": logrus.Fields{"message": err.Error()},
		}).Fatalf("failed to create sdk")
	}
	return sdk
}
