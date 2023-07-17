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

package service

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/helpers"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/types"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	glogrus "github.com/mia-platform/glogger/v4/loggers/logrus"
	"github.com/mia-platform/go-crud-service-client"
	"github.com/sirupsen/logrus"
)

// TODO: handle pagination!
const BINDINGS_MAX_PAGE_SIZE = 200

type RevokeRequestBody struct {
	Subjects    []string `json:"subjects,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	ResourceIDs []string `json:"resourceIds"`
}
type RevokeResponseBody struct {
	DeletedBindings  int `json:"deletedBindings"`
	ModifiedBindings int `json:"modifiedBindings"`
}

func revokeHandler(w http.ResponseWriter, r *http.Request) {
	logger := glogrus.FromContext(r.Context())
	env, err := config.GetEnv(r.Context())
	if err != nil {
		utils.FailResponseWithCode(w, http.StatusInternalServerError, err.Error(), utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	reqBody := RevokeRequestBody{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		utils.FailResponseWithCode(w, http.StatusInternalServerError, err.Error(), utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	resourceType := mux.Vars(r)["resourceType"]
	if resourceType != "" && len(reqBody.ResourceIDs) == 0 {
		utils.FailResponseWithCode(w, http.StatusBadRequest, "empty resources list", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}
	if len(reqBody.Subjects) == 0 && len(reqBody.Groups) == 0 {
		utils.FailResponseWithCode(w, http.StatusBadRequest, "empty subjects and groups lists", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	client, err := crud.NewClient[types.Binding](crud.ClientOptions{
		BaseURL: env.BindingsCrudServiceURL,
		Headers: helpers.GetHeadersToProxy(r, env.GetAdditionalHeadersToProxy()),
	})
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed crud setup")
		utils.FailResponseWithCode(w, http.StatusInternalServerError, err.Error(), utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	query := buildQuery(resourceType, reqBody.ResourceIDs, reqBody.Subjects, reqBody.Groups)
	bindings, err := client.List(r.Context(), crud.Options{
		Filter: crud.Filter{
			MongoQuery: query,
			Limit:      BINDINGS_MAX_PAGE_SIZE,
		},
	})
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed crud request")
		utils.FailResponseWithCode(w, http.StatusInternalServerError, "failed crud request for finding bindings", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	bindingsToPatch, bindingsToDelete := prepareBindings(bindings, reqBody)

	var deleteCrudResponse int
	var patchCrudResponse int

	if len(bindingsToDelete) > 0 {
		query := buildQueryForBindingsToDelete(bindingsToDelete)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed delete query crud setup")
			utils.FailResponseWithCode(w, http.StatusInternalServerError, "failed delete query crud setup", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
			return
		}

		logger.WithFields(logrus.Fields{
			"bindingsToDeleteQuery": query,
			"bindingsToDelete":      len(bindingsToDelete),
		}).Debug("generated query for bindings to delete")

		deleteCrudResponse, err = client.DeleteMany(r.Context(), crud.Options{Filter: crud.Filter{MongoQuery: query}})
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed crud request")
			utils.FailResponseWithCode(w, http.StatusInternalServerError, "failed crud request for deleting unused bindings", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
			return
		}
		logger.WithField("deletedBindings", deleteCrudResponse).Debug("binding deletion finished")
	}

	if len(bindingsToPatch) > 0 {
		body := buildRequestBodyForBindingsToPatch(bindingsToPatch)

		patchCrudResponse, err = client.PatchBulk(r.Context(), body, crud.Options{})
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed crud request")
			utils.FailResponseWithCode(
				w,
				http.StatusInternalServerError,
				fmt.Sprintf("failed crud request to modify existing bindings. removed bindings: %d", deleteCrudResponse),
				utils.GENERIC_BUSINESS_ERROR_MESSAGE,
			)
			return
		}
		logger.WithField("updatedBindings", patchCrudResponse).Debug("binding updated finished")
	}

	response := RevokeResponseBody{
		DeletedBindings:  deleteCrudResponse,
		ModifiedBindings: patchCrudResponse,
	}
	responseBytes, err := json.Marshal(response)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed response body")
		utils.FailResponseWithCode(
			w,
			http.StatusInternalServerError,
			fmt.Sprintf("failed response body creation. removed bindings: %d, modified bindings: %d", deleteCrudResponse, patchCrudResponse),
			utils.GENERIC_BUSINESS_ERROR_MESSAGE,
		)
	}
	if _, err := w.Write(responseBytes); err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Warn("failed response write")
	}
}

type GrantRequestBody struct {
	ResourceID  string   `json:"resourceId"`
	Subjects    []string `json:"subjects"`
	Groups      []string `json:"groups"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}
type GrantResponseBody struct {
	BindingID string `json:"bindingId"`
}

func grantHandler(w http.ResponseWriter, r *http.Request) {
	logger := glogrus.FromContext(r.Context())
	env, err := config.GetEnv(r.Context())
	if err != nil {
		utils.FailResponseWithCode(w, http.StatusInternalServerError, err.Error(), utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	reqBody := GrantRequestBody{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		utils.FailResponseWithCode(w, http.StatusInternalServerError, err.Error(), utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	resourceType := mux.Vars(r)["resourceType"]
	if resourceType != "" && reqBody.ResourceID == "" {
		utils.FailResponseWithCode(w, http.StatusBadRequest, "missing resource id", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	if len(reqBody.Groups) == 0 && len(reqBody.Permissions) == 0 && len(reqBody.Subjects) == 0 && len(reqBody.Roles) == 0 {
		utils.FailResponseWithCode(w, http.StatusBadRequest, "missing body fields, one of groups, permissions, subjects or roles is required", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	client, err := crud.NewClient[types.Binding](crud.ClientOptions{
		BaseURL: env.BindingsCrudServiceURL,
		Headers: helpers.GetHeadersToProxy(r, env.GetAdditionalHeadersToProxy()),
	})
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed crud setup")
		utils.FailResponseWithCode(w, http.StatusInternalServerError, err.Error(), utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	bindingToCreate := types.Binding{
		BindingID:   uuid.New().String(),
		Groups:      reqBody.Groups,
		Permissions: reqBody.Permissions,
		Roles:       reqBody.Roles,
		Subjects:    reqBody.Subjects,
	}

	if resourceType != "" {
		bindingToCreate.Resource = &types.Resource{
			ResourceType: resourceType,
			ResourceID:   reqBody.ResourceID,
		}
	}

	bindingIDCreated, err := client.Create(r.Context(), bindingToCreate, crud.Options{})
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed crud request")
		utils.FailResponseWithCode(w, http.StatusInternalServerError, "failed crud request for creating bindings", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}
	logger.WithFields(logrus.Fields{
		"createdBindingObjectId": utils.SanitizeString(bindingIDCreated),
		"createdBindingId":       utils.SanitizeString(bindingToCreate.BindingID),
		"resourceId":             utils.SanitizeString(reqBody.ResourceID),
		"resourceType":           utils.SanitizeString(resourceType),
	}).Debug("created bindings")

	response := GrantResponseBody{BindingID: bindingToCreate.BindingID}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed response body")
		utils.FailResponseWithCode(
			w,
			http.StatusInternalServerError,
			"failed response body creation",
			utils.GENERIC_BUSINESS_ERROR_MESSAGE,
		)
	}
	if _, err := w.Write(responseBytes); err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Warn("failed response write")
	}
}

func buildQuery(resourceType string, resourceIDs []string, subjects []string, groups []string) map[string]interface{} {
	queryPartForSubjectOrGroups := map[string]interface{}{
		"$or": []map[string]interface{}{},
	}

	if len(subjects) > 0 {
		subjectQuery := map[string]interface{}{"subjects": map[string]interface{}{"$in": subjects}}
		tempQuery := queryPartForSubjectOrGroups["$or"].([]map[string]interface{})
		queryPartForSubjectOrGroups["$or"] = append(tempQuery, subjectQuery)
	}
	if len(groups) > 0 {
		groupsQuery := map[string]interface{}{"groups": map[string]interface{}{"$in": groups}}
		tempQuery := queryPartForSubjectOrGroups["$or"].([]map[string]interface{})
		queryPartForSubjectOrGroups["$or"] = append(tempQuery, groupsQuery)
	}

	if resourceType == "" {
		return queryPartForSubjectOrGroups
	}

	query := map[string]interface{}{
		"$and": []map[string]interface{}{
			{
				"resource.resourceType": resourceType,
				"resource.resourceId":   map[string]interface{}{"$in": resourceIDs},
			},
			queryPartForSubjectOrGroups,
		},
	}

	return query
}

func buildQueryForBindingsToDelete(bindingsToDelete []types.Binding) map[string]interface{} {
	bindingsIds := make([]string, len(bindingsToDelete))
	for i := 0; i < len(bindingsToDelete); i++ {
		bindingsIds[i] = bindingsToDelete[i].BindingID
	}

	query := map[string]interface{}{
		"bindingId": map[string]interface{}{
			"$in": bindingsIds,
		},
	}
	return query
}

func buildRequestBodyForBindingsToPatch(bindingsToPatch []types.Binding) crud.PatchBulkBody {
	patches := make(crud.PatchBulkBody, len(bindingsToPatch))
	for i := 0; i < len(bindingsToPatch); i++ {
		currentBinding := bindingsToPatch[i]
		patches[i] = crud.PatchBulkItem{
			Filter: crud.PatchBulkFilter{
				Fields: map[string]string{
					"bindingId": currentBinding.BindingID,
				},
			},
			Update: crud.PatchBody{
				Set: types.BindingUpdate{
					Subjects: currentBinding.Subjects,
					Groups:   currentBinding.Groups,
				},
			},
		}
	}
	return patches
}

func prepareBindings(bindings []types.Binding, reqBody RevokeRequestBody) ([]types.Binding, []types.Binding) {
	var bindingToPatch []types.Binding
	var bindingToDelete []types.Binding

	for _, binding := range bindings {
		binding.Subjects = utils.FilterList(binding.Subjects, reqBody.Subjects)
		if binding.Subjects == nil {
			binding.Subjects = []string{}
		}
		binding.Groups = utils.FilterList(binding.Groups, reqBody.Groups)
		if binding.Groups == nil {
			binding.Groups = []string{}
		}

		if len(binding.Subjects) == 0 && len(binding.Groups) == 0 {
			bindingToDelete = append(bindingToDelete, binding)
			continue
		}

		bindingToPatch = append(bindingToPatch, binding)
	}

	return bindingToPatch, bindingToDelete
}
