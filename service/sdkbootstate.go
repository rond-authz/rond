// Copyright 2023 Mia srl
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

package service

import (
	"sync"

	"github.com/rond-authz/rond/sdk"
)

type SDKBootState struct {
	// wg   *sync.WaitGroup
	mtx  *sync.Mutex
	rond sdk.OASEvaluatorFinder
}

func NewSDKBootState() *SDKBootState {
	// wg := &sync.WaitGroup{}
	// wg.Add(1)
	return &SDKBootState{
		// wg: wg,
		mtx: &sync.Mutex{},
	}
}

// func (s *SDKBootState) Wait() sdk.OASEvaluatorFinder {
// 	s.wg.Wait()
// 	return s.rond
// }

func (s *SDKBootState) Ready(rond sdk.OASEvaluatorFinder) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.rond = rond
	// s.wg.Done()
}

func (s *SDKBootState) Get() sdk.OASEvaluatorFinder {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return s.rond
}
