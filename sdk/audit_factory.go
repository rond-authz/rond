// Copyright 2024 Mia srl
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

package sdk

import (
	"github.com/rond-authz/rond/internal/audit"
	"github.com/rond-authz/rond/logging"
)

func buildAuditAgent(options *Options, logger logging.Logger) audit.AgentPool {
	if options == nil || options.EvaluatorOptions == nil {
		return audit.NewNoopAgentPool()
	}
	if !options.EvaluatorOptions.EnableAuditTracing {
		return audit.NewNoopAgentPool()
	}

	auditOptions := options.EvaluatorOptions.AuditTracingOptions

	poolOptions := audit.AgentPoolOptions{
		Logger:   logger,
		Labels:   options.AuditLabels,
		Storages: auditOptions.StorageMode,
		MongoDBStorage: audit.MongoAgentPoolOptions{
			Client:         auditOptions.MongoDBClient,
			CollectionName: auditOptions.AuditCollectionName,
		},
	}
	return audit.NewAgentPool(poolOptions)
}
