package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/types"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"
	"gotest.tools/v3/assert"
)

func TestRevokeHandler(t *testing.T) {

	ctx := createContext(t,
		context.Background(),
		config.EnvironmentVariables{BindingsCrudServiceURL: "http://crud-service/bindings/"},
		nil,
		nil,
		nil,
		nil,
	)

	t.Run("400 on resourceIds", func(t *testing.T) {
		reqBody := setupRevokeRequestBody(t, RevokeRequestBody{
			Subjects: []string{"piero"},
			Groups:   []string{"litfiba"},
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewBuffer(reqBody))
		assert.NilError(t, err, "unexpcted error")
		w := httptest.NewRecorder()

		revokeHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusBadRequest)
	})

	t.Run("400 on missing subjects and groups", func(t *testing.T) {
		reqBody := setupRevokeRequestBody(t, RevokeRequestBody{
			Subjects:    []string{},
			Groups:      []string{},
			ResourceIDs: []string{"mike"},
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewBuffer(reqBody))
		assert.NilError(t, err, "unexpcted error")
		w := httptest.NewRecorder()

		revokeHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusBadRequest)
	})

	reqBody := setupRevokeRequestBody(t, RevokeRequestBody{
		Subjects:    []string{"piero"},
		Groups:      []string{"litfiba"},
		ResourceIDs: []string{"mike"},
	})

	t.Run("error on CRUD error", func(t *testing.T) {
		defer gock.Flush()

		responseBody := map[string]interface{}{"answer": float64(42)}
		gock.DisableNetworking()
		gock.New("http://crud-service").
			Get("/bindings/").
			Reply(http.StatusBadRequest).
			JSON(responseBody)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewBuffer(reqBody))
		assert.NilError(t, err, "unexpcted error")
		w := httptest.NewRecorder()

		revokeHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusInternalServerError)
	})

	t.Run("error on CRUD delete API", func(t *testing.T) {
		defer gock.Flush()

		bindingsFromCrud := []types.Binding{
			{
				BindingID: "bindingToDelete",
				Subjects:  []string{"piero"},
				Resource: types.Resource{
					ResourceType: "project",
					ResourceID:   "mike",
				},
			},
		}
		gock.DisableNetworking()
		gock.New("http://crud-service").
			Get("/bindings/").
			Reply(http.StatusOK).
			JSON(bindingsFromCrud)

		gock.New("http://crud-service").
			Delete("/bindings/").
			Reply(http.StatusInternalServerError).
			JSON(map[string]interface{}{"statusCode": "500", "error": "InternalServerError", "message": "some message"})

		reqBody := setupRevokeRequestBody(t, RevokeRequestBody{
			Subjects:    []string{"piero"},
			ResourceIDs: []string{"mike"},
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/revoke/bindings/resource/project", bytes.NewBuffer(reqBody))
		assert.NilError(t, err, "unexpcted error")
		w := httptest.NewRecorder()

		revokeHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusInternalServerError)
	})

	t.Run("does not invoke delete API if not necessary", func(t *testing.T) {
		defer gock.Flush()

		bindingsFromCrud := []types.Binding{
			{
				BindingID: "bindingToDelete",
				Subjects:  []string{"piero", "ghigo"},
				Resource: types.Resource{
					ResourceType: "project",
					ResourceID:   "mike",
				},
			},
		}

		gock.DisableNetworking()
		gock.New("http://crud-service").
			Get("/bindings/").
			Reply(http.StatusOK).
			JSON(bindingsFromCrud)

		gock.New("http://crud-service").
			Patch("/bindings/").
			Reply(http.StatusOK)

		reqBody := setupRevokeRequestBody(t, RevokeRequestBody{
			Subjects:    []string{"piero"},
			ResourceIDs: []string{"mike"},
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/revoke/bindings/resource/project", bytes.NewBuffer(reqBody))
		assert.NilError(t, err, "unexpcted error")
		w := httptest.NewRecorder()

		revokeHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusOK)
	})

	t.Run("performs correct delete query only on subject", func(t *testing.T) {
		defer gock.Flush()

		bindingsFromCrud := []types.Binding{
			{
				BindingID: "bindingToDelete",
				Subjects:  []string{"piero"},
				Resource: types.Resource{
					ResourceType: "project",
					ResourceID:   "mike",
				},
			},
		}
		gock.DisableNetworking()
		gock.New("http://crud-service").
			Get("/bindings/").
			AddMatcher(func(req *http.Request, greq *gock.Request) (bool, error) {
				mongoQueryString := req.URL.Query().Get("_q")

				match := mongoQueryString == `{"$and":[{"resource.resourceId":{"$in":["mike"]},"resource.resourceType":""},{"$or":[{"subjects":{"$in":["piero"]}}]}]}`

				return match, nil
			}).
			Reply(http.StatusOK).
			JSON(bindingsFromCrud)

		gock.New("http://crud-service").
			Delete("/bindings/").
			AddMatcher(func(req *http.Request, ereq *gock.Request) (bool, error) {
				mongoQuery := req.URL.Query().Get("_q")
				match := mongoQuery == `{"bindingId":{"$in":["bindingToDelete"]}}`
				return match, nil
			}).
			Reply(http.StatusOK).
			BodyString("1")

		reqBody := setupRevokeRequestBody(t, RevokeRequestBody{
			Subjects:    []string{"piero"},
			ResourceIDs: []string{"mike"},
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/revoke/bindings/resource/project", bytes.NewBuffer(reqBody))
		assert.NilError(t, err, "unexpcted error")
		w := httptest.NewRecorder()

		revokeHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusOK)
	})

	t.Run("performs correct delete query only on subject", func(t *testing.T) {
		defer gock.Flush()

		bindingsFromCrud := []types.Binding{
			{
				BindingID: "bindingToDelete",
				Groups:    []string{"litfiba"},
				Resource: types.Resource{
					ResourceType: "project",
					ResourceID:   "mike",
				},
			},
		}
		gock.DisableNetworking()
		gock.New("http://crud-service").
			Get("/bindings/").
			AddMatcher(func(req *http.Request, greq *gock.Request) (bool, error) {
				mongoQueryString := req.URL.Query().Get("_q")

				match := mongoQueryString == `{"$and":[{"resource.resourceId":{"$in":["mike"]},"resource.resourceType":""},{"$or":[{"groups":{"$in":["litfiba"]}}]}]}`

				return match, nil
			}).
			Reply(http.StatusOK).
			JSON(bindingsFromCrud)

		gock.New("http://crud-service").
			Delete("/bindings/").
			AddMatcher(func(req *http.Request, ereq *gock.Request) (bool, error) {
				mongoQuery := req.URL.Query().Get("_q")
				match := mongoQuery == `{"bindingId":{"$in":["bindingToDelete"]}}`
				return match, nil
			}).
			Reply(http.StatusOK).
			BodyString("1")

		reqBody := setupRevokeRequestBody(t, RevokeRequestBody{
			Groups:      []string{"litfiba"},
			ResourceIDs: []string{"mike"},
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/revoke/bindings/resource/project", bytes.NewBuffer(reqBody))
		assert.NilError(t, err, "unexpcted error")
		w := httptest.NewRecorder()

		revokeHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusOK)
	})

	t.Run("performs correct patch API invocation", func(t *testing.T) {
		defer gock.Flush()

		bindingsFromCrud := []types.Binding{
			{
				BindingID: "litfiba",
				Subjects:  []string{"piero", "ghigo"},
				Resource: types.Resource{
					ResourceType: "project",
					ResourceID:   "mike",
				},
			},
		}
		gock.DisableNetworking()
		gock.New("http://crud-service").
			Get("/bindings/").
			Reply(http.StatusOK).
			JSON(bindingsFromCrud)

		gock.New("http://crud-service").
			Patch("/bindings/").
			AddMatcher(func(req *http.Request, ereq *gock.Request) (bool, error) {
				var body []PatchItem
				err := json.NewDecoder(req.Body).Decode(&body)
				assert.NilError(t, err, "unxpected error parsing body in matcher")

				require.Equal(t, []PatchItem{
					{
						Filter: types.BindingFilter{BindingID: "litfiba"},
						Update: UpdateCommand{
							SetCommand: types.BindingUpdate{
								Subjects: []string{"ghigo"},
								Groups:   []string{},
							},
						},
					},
				}, body)
				return true, nil
			}).
			Reply(http.StatusOK).
			BodyString("1")

		reqBody := setupRevokeRequestBody(t, RevokeRequestBody{
			Subjects:    []string{"piero"},
			ResourceIDs: []string{"mike"},
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/revoke/bindings/resource/project", bytes.NewBuffer(reqBody))
		assert.NilError(t, err, "unexpcted error")
		w := httptest.NewRecorder()

		revokeHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusOK)
	})

	t.Run("performs correct delete and patch APIs", func(t *testing.T) {
		defer gock.Flush()

		bindingsFromCrud := []types.Binding{
			{
				BindingID: "oasis",
				Subjects:  []string{"liam", "noel"},
				Groups:    []string{"brutte_band"},
				Resource: types.Resource{
					ResourceType: "project",
					ResourceID:   "mike",
				},
			},
			{
				BindingID: "litfiba",
				Subjects:  []string{"piero", "ghigo"},
				Groups:    []string{"brutte_band"},
				Resource: types.Resource{
					ResourceType: "project",
					ResourceID:   "mike",
				},
			},
		}
		gock.DisableNetworking()
		gock.New("http://crud-service").
			Get("/bindings/").
			Reply(http.StatusOK).
			JSON(bindingsFromCrud)

		gock.New("http://crud-service").
			Delete("/bindings/").
			AddMatcher(func(req *http.Request, ereq *gock.Request) (bool, error) {
				mongoQuery := req.URL.Query().Get("_q")
				match := mongoQuery == `{"bindingId":{"$in":["oasis"]}}`
				return match, nil
			}).
			Reply(http.StatusOK).
			BodyString("1")

		gock.New("http://crud-service").
			Patch("/bindings/").
			AddMatcher(func(req *http.Request, ereq *gock.Request) (bool, error) {
				var body []PatchItem

				err := json.NewDecoder(req.Body).Decode(&body)
				assert.NilError(t, err, "unxpected error parsing body in matcher")

				require.Equal(t, []PatchItem{
					{
						Filter: types.BindingFilter{BindingID: "litfiba"},
						Update: UpdateCommand{
							SetCommand: types.BindingUpdate{
								Subjects: []string{"ghigo"},
								Groups:   []string{},
							},
						},
					},
				}, body)
				return true, nil
			}).
			Reply(http.StatusOK).
			BodyString("1")

		reqBody := setupRevokeRequestBody(t, RevokeRequestBody{
			Subjects:    []string{"piero", "liam", "noel"},
			Groups:      []string{"brutte_band"},
			ResourceIDs: []string{"mike"},
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/revoke/bindings/resource/project", bytes.NewBuffer(reqBody))
		assert.NilError(t, err, "unexpcted error")
		w := httptest.NewRecorder()

		revokeHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusOK)

		revokeResponse := RevokeResponseBody{}
		err = json.NewDecoder(w.Body).Decode(&revokeResponse)
		assert.NilError(t, err)
	})
}

func TestBindingsToUpdate(t *testing.T) {
	t.Run("expect to generate correct bindings to update", func(t *testing.T) {
		bindingsFromCrud := []types.Binding{
			{
				Subjects: []string{"0000", "1111"},
				Groups:   []string{"delete_project"},
			},
		}
		requestBody := RevokeRequestBody{
			Subjects: []string{"0000"},
			Groups:   []string{"delete_project"},
		}

		bindingsToPatch, bindingsToDelete := prepareBindings(bindingsFromCrud, requestBody)
		require.Equal(t, []types.Binding{
			{
				Subjects: []string{"1111"},
				Groups:   []string{},
			},
		}, bindingsToPatch)
		require.Nil(t, bindingsToDelete)
	})

	t.Run("expect to generate correct bindings to delete", func(t *testing.T) {
		bindingsFromCrud := []types.Binding{
			{
				BindingID: "bindingToDelete",
				Subjects:  []string{"0000", "1111"},
				Groups:    []string{"delete_project"},
			},
		}
		requestBody := RevokeRequestBody{
			Subjects: []string{"0000", "1111"},
			Groups:   []string{"delete_project"},
		}

		bindingsToPatch, bindingsToDelete := prepareBindings(bindingsFromCrud, requestBody)
		require.Nil(t, bindingsToPatch)
		require.Equal(t, []types.Binding{
			{
				BindingID: "bindingToDelete",
				Subjects:  []string{},
				Groups:    []string{},
			},
		}, bindingsToDelete)
	})

	t.Run("expect to generate correct bindings to update and to delete", func(t *testing.T) {
		bindingsFromCrud := []types.Binding{
			{
				BindingID: "1",
				Subjects:  []string{"0000"},
			},
			{
				BindingID: "2",
				Groups:    []string{"my_group"},
			},
			{
				BindingID: "3",
				Subjects:  []string{"0000", "1111"},
			},
			{
				BindingID: "4",
				Subjects:  []string{"0000"},
				Groups:    []string{"my_group", "second_group"},
			},
		}
		requestBody := RevokeRequestBody{
			Subjects: []string{"0000"},
			Groups:   []string{"my_group"},
		}

		bindingsToPatch, bindingsToDelete := prepareBindings(bindingsFromCrud, requestBody)
		require.Equal(t, []types.Binding{
			{
				BindingID: "3",
				Subjects:  []string{"1111"},
				Groups:    []string{},
			},
			{
				BindingID: "4",
				Subjects:  []string{},
				Groups:    []string{"second_group"},
			},
		}, bindingsToPatch)

		require.Equal(t, []types.Binding{
			{
				BindingID: "1",
				Subjects:  []string{},
				Groups:    []string{},
			},
			{
				BindingID: "2",
				Subjects:  []string{},
				Groups:    []string{},
			},
		}, bindingsToDelete)
	})
}

func setupRevokeRequestBody(t *testing.T, body RevokeRequestBody) []byte {
	t.Helper()

	bodyBytes, err := json.Marshal(body)
	assert.NilError(t, err, "unexpected error")
	return bodyBytes
}
