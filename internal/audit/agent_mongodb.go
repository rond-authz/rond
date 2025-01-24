// Copyright 2025 Mia srl
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

package audit

import (
	"context"
	"fmt"

	"github.com/rond-authz/rond/types"
)

var ErrAuditNotInserted = fmt.Errorf("audit not inserted")

type mongoDBAgent struct {
	c              types.MongoClient
	collectionName string

	cache AuditCache
}

func newMongoDBAgent(client types.MongoClient, auditCollectionName string) Agent {
	return &mongoDBAgent{
		c:              client,
		collectionName: auditCollectionName,

		cache: &SingleRecordCache{},
	}
}

func (m *mongoDBAgent) Trace(ctx context.Context, auditInput Audit) error {
	trail := auditInput.toPrint(m.cache.Load()).serialize()
	if m.c == nil {
		return fmt.Errorf("%w: invalid mongo client", ErrAuditNotInserted)
	}

	result, err := m.c.Collection(m.collectionName).InsertOne(ctx, trail)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrAuditNotInserted, err)
	}

	if result.InsertedID == nil {
		return ErrAuditNotInserted
	}

	return nil
}

func (m *mongoDBAgent) Cache() AuditCache {
	return m.cache
}
