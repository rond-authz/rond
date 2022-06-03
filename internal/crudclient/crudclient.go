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

package crudclient

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/davidebianchi/go-jsonclient"
	"github.com/rond-authz/rond/helpers"
)

// CRUD struct.
type CRUD struct {
	httpClient *jsonclient.Client
}

// New creates new CRUDClient.
func New(apiURL string) (*CRUD, error) {
	apiURLWithoutFinalSlash := strings.TrimSuffix(apiURL, "/")

	opts := jsonclient.Options{
		BaseURL: fmt.Sprintf("%s/", apiURLWithoutFinalSlash),
	}
	httpClient, err := jsonclient.New(opts)
	if err != nil {
		return nil, err
	}

	crudClient := &CRUD{
		httpClient,
	}
	return crudClient, nil
}

// Get fetch item by id on CRUD.
func (crud CRUD) Get(ctx context.Context, queryParam string, responseBody interface{}) error {
	req, err := crud.httpClient.NewRequestWithContext(ctx, http.MethodGet, "?"+queryParam, nil)
	if err != nil {
		return err
	}

	helpers.SetHeadersToProxy(ctx, req.Header)

	if _, err := crud.httpClient.Do(req, responseBody); err != nil {
		return err
	}
	return nil
}

func (crud CRUD) Post(ctx context.Context, body interface{}, responseBody interface{}) error {
	req, err := crud.httpClient.NewRequestWithContext(ctx, http.MethodPost, "", body)
	if err != nil {
		return err
	}

	helpers.SetHeadersToProxy(ctx, req.Header)

	_, err = crud.httpClient.Do(req, responseBody)
	if err != nil {
		return err
	}

	return nil
}

func (crud CRUD) Delete(ctx context.Context, queryParam string, responseBody interface{}) error {
	req, err := crud.httpClient.NewRequestWithContext(ctx, http.MethodDelete, "?"+queryParam, nil)
	if err != nil {
		return err
	}

	helpers.SetHeadersToProxy(ctx, req.Header)

	if _, err := crud.httpClient.Do(req, responseBody); err != nil {
		return err
	}
	return nil
}

func (crud CRUD) PatchBulk(ctx context.Context, requestBody interface{}, responseBody interface{}) error {
	req, err := crud.httpClient.NewRequestWithContext(ctx, http.MethodPatch, "", requestBody)
	if err != nil {
		return err
	}

	helpers.SetHeadersToProxy(ctx, req.Header)

	if _, err := crud.httpClient.Do(req, responseBody); err != nil {
		return err
	}
	return nil
}

// IsHealthy checks if crud is healthy.
func (crud CRUD) IsHealthy(ctx context.Context) error {
	req, err := crud.httpClient.NewRequest(http.MethodGet, "/-/healthz", nil)
	if err != nil {
		return err
	}

	helpers.SetHeadersToProxy(ctx, req.Header)

	if _, err := crud.httpClient.Do(req, nil); err != nil {
		return err
	}
	return nil
}
