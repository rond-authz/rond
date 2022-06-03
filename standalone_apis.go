package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/crudclient"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/types"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
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
	logger := glogger.Get(r.Context())
	env, err := config.GetEnv(r.Context())
	if err != nil {
		failResponseWithCode(w, http.StatusInternalServerError, err.Error(), GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	reqBody := RevokeRequestBody{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		failResponseWithCode(w, http.StatusInternalServerError, err.Error(), GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}
	logger.WithField("request", reqBody).Debug("revoke request body")

	if len(reqBody.ResourceIDs) == 0 {
		failResponseWithCode(w, http.StatusBadRequest, "empty resources list", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}
	if len(reqBody.Subjects) == 0 && len(reqBody.Groups) == 0 {
		failResponseWithCode(w, http.StatusBadRequest, "empty subjects and groups lists", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	bindings := make([]types.Binding, 0)

	client, err := crudclient.New(env.BindingsCrudServiceURL)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed crud setup")
		failResponseWithCode(w, http.StatusInternalServerError, err.Error(), GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	resourceType := mux.Vars(r)["resourceType"]
	query, err := buildQuery(resourceType, reqBody.ResourceIDs, reqBody.Subjects, reqBody.Groups)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed find query crud setup")
		failResponseWithCode(w, http.StatusInternalServerError, "failed find query crud setup", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	if err := client.Get(r.Context(), fmt.Sprintf("_q=%s&_l=%d", string(query), BINDINGS_MAX_PAGE_SIZE), &bindings); err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed crud request")
		failResponseWithCode(w, http.StatusInternalServerError, "failed crud request for finding bindings", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	bindingsToPatch, bindingsToDelete := prepareBindings(bindings, reqBody)

	var deleteCrudResponse int
	var patchCrudResponse int

	if len(bindingsToDelete) > 0 {
		query, err := buildQueryForBindingsToDelete(bindingsToDelete)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed delete query crud setup")
			failResponseWithCode(w, http.StatusInternalServerError, "failed delete query crud setup", GENERIC_BUSINESS_ERROR_MESSAGE)
			return
		}

		logger.WithFields(logrus.Fields{
			"bindingsToDeleteQuery": query,
			"bindingsToDelete":      len(bindingsToDelete),
		}).Debug("generated query for bindings to delete")

		if err := client.Delete(r.Context(), fmt.Sprintf("_q=%s", string(query)), &deleteCrudResponse); err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed crud request")
			failResponseWithCode(w, http.StatusInternalServerError, "failed crud request for deleting unused bindings", GENERIC_BUSINESS_ERROR_MESSAGE)
			return
		}
		logger.WithField("deletedBindings", deleteCrudResponse).Debug("binding deletion finished")
	}

	if len(bindingsToPatch) > 0 {
		body := buildRequestBodyForBindingsToPatch(bindingsToPatch)

		if err := client.PatchBulk(r.Context(), body, &patchCrudResponse); err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed crud request")
			failResponseWithCode(
				w,
				http.StatusInternalServerError,
				fmt.Sprintf("failed crud request to modify existing bindings. removed bindings: %d", deleteCrudResponse),
				GENERIC_BUSINESS_ERROR_MESSAGE,
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
		failResponseWithCode(
			w,
			http.StatusInternalServerError,
			fmt.Sprintf("failed response body creation. removed bindings: %d, modified bindings: %d", deleteCrudResponse, patchCrudResponse),
			GENERIC_BUSINESS_ERROR_MESSAGE,
		)
	}
	w.Write(responseBytes)
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
	logger := glogger.Get(r.Context())
	env, err := config.GetEnv(r.Context())
	if err != nil {
		failResponseWithCode(w, http.StatusInternalServerError, err.Error(), GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	reqBody := GrantRequestBody{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		failResponseWithCode(w, http.StatusInternalServerError, err.Error(), GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}
	logger.WithField("request", reqBody).Debug("grant request body")

	if reqBody.ResourceID == "" {
		failResponseWithCode(w, http.StatusBadRequest, "missing resource id", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	if len(reqBody.Groups) == 0 && len(reqBody.Permissions) == 0 && len(reqBody.Subjects) == 0 && len(reqBody.Roles) == 0 {
		failResponseWithCode(w, http.StatusBadRequest, "missing body fields, one of groups, permissions, subjects or roles is required", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	client, err := crudclient.New(env.BindingsCrudServiceURL)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed crud setup")
		failResponseWithCode(w, http.StatusInternalServerError, err.Error(), GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	resourceType := mux.Vars(r)["resourceType"]
	bindingToCreate := types.Binding{
		BindingID: uuid.New().String(),
		Groups:    reqBody.Groups,
		Roles:     reqBody.Roles,
		Subjects:  reqBody.Subjects,
		Resource: types.Resource{
			ResourceType: resourceType,
			ResourceID:   reqBody.ResourceID,
		},
	}

	var bindingIDCreated types.BindingCreateResponse
	if err := client.Post(r.Context(), &bindingToCreate, &bindingIDCreated); err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed crud request")
		failResponseWithCode(w, http.StatusInternalServerError, "failed crud request for creating bindings", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}
	logger.WithFields(logrus.Fields{
		"createdBindingObjectId": bindingIDCreated.ObjectID,
		"createdBindingId":       bindingToCreate.BindingID,
		"resourceId":             reqBody.ResourceID,
		"resourceType":           resourceType,
	}).Debug("created bindings")

	response := GrantResponseBody{BindingID: bindingToCreate.BindingID}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed response body")
		failResponseWithCode(
			w,
			http.StatusInternalServerError,
			"failed response body creation",
			GENERIC_BUSINESS_ERROR_MESSAGE,
		)
	}
	w.Write(responseBytes)
}

func buildQuery(resourceType string, resourceIDs []string, subjects []string, groups []string) ([]byte, error) {
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

	query := map[string]interface{}{
		"$and": []map[string]interface{}{
			{
				"resource.resourceType": resourceType,
				"resource.resourceId":   map[string]interface{}{"$in": resourceIDs},
			},
			queryPartForSubjectOrGroups,
		},
	}

	return json.Marshal(query)
}

func buildQueryForBindingsToDelete(bindingsToDelete []types.Binding) ([]byte, error) {
	bindingsIds := make([]string, len(bindingsToDelete))
	for i := 0; i < len(bindingsToDelete); i++ {
		bindingsIds[i] = bindingsToDelete[i].BindingID
	}

	query := map[string]interface{}{
		"bindingId": map[string]interface{}{
			"$in": bindingsIds,
		},
	}
	return json.Marshal(query)
}

type UpdateCommand struct {
	SetCommand types.BindingUpdate `json:"$set"`
}
type PatchItem struct {
	Filter types.BindingFilter `json:"filter"`
	Update UpdateCommand       `json:"update"`
}

func buildRequestBodyForBindingsToPatch(bindingsToPatch []types.Binding) []PatchItem {
	patches := make([]PatchItem, len(bindingsToPatch))
	for i := 0; i < len(bindingsToPatch); i++ {
		currentBinding := bindingsToPatch[i]
		patches[i] = PatchItem{
			Filter: types.BindingFilter{BindingID: currentBinding.BindingID},
			Update: UpdateCommand{
				SetCommand: types.BindingUpdate{
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
