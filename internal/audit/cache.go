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

package audit

import "sync"

type Data map[string]any

type AuditCache interface {
	Store(d Data)
	Load() Data
}

type SingleRecordCache struct {
	sync.RWMutex

	data Data
}

func (c *SingleRecordCache) Store(d Data) {
	c.Lock()
	defer c.Unlock()

	if c.data == nil {
		c.data = make(Data)
	}

	for k, v := range d {
		c.data[k] = v
	}
}

func (c *SingleRecordCache) Load() Data {
	c.RLock()
	defer c.RUnlock()

	return c.data
}
