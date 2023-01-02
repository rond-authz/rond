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

package openapi

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rond-authz/rond/internal/utils"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type RouterInfoKey struct{}

type RouterInfo struct {
	MatchedPath   string
	RequestedPath string
	Method        string
}

func WithRouterInfo(logger *logrus.Entry, requestContext context.Context, req *http.Request) context.Context {
	pathTemplate := getPathTemplateOrDefaultToEmptyString(logger, req)
	return context.WithValue(requestContext, RouterInfoKey{}, RouterInfo{
		MatchedPath:   utils.SanitizeString(pathTemplate),
		RequestedPath: utils.SanitizeString(req.URL.Path),
		Method:        utils.SanitizeString(req.Method),
	})
}

func getPathTemplateOrDefaultToEmptyString(logger *logrus.Entry, req *http.Request) string {
	var pathTemplate string
	route := mux.CurrentRoute(req)
	if route != nil {
		var err error
		if pathTemplate, err = route.GetPathTemplate(); err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Warn("path template is empty")
			return ""
		}
	}
	return pathTemplate
}

func GetRouterInfo(requestContext context.Context) (RouterInfo, error) {
	routerInfo, ok := requestContext.Value(RouterInfoKey{}).(RouterInfo)
	if !ok {
		return RouterInfo{}, fmt.Errorf("no router info found")
	}
	return routerInfo, nil
}
