package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"
	"gotest.tools/v3/assert"
)

func TestFetchOpenAPI(t *testing.T) {
	t.Run("fetches json OAS", func(t *testing.T) {
		defer gock.Off()

		gock.New("http://localhost:3000").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMock.json")

		url := "http://localhost:3000/documentation/json"

		openApiSpec, err := fetchOpenAPI(url)

		assert.Assert(t, gock.IsDone(), "Mock has not been invoked")
		assert.Assert(t, err == nil, "unexpected error")
		assert.Assert(t, openApiSpec != nil, "unexpected nil result")
		assert.DeepEqual(t, openApiSpec.Paths, OpenAPIPaths{
			"/users/": PathVerbs{
				"get": VerbConfig{
					Permission: XPermission{
						AllowPermission: "foobar",
					},
				},
				"post": VerbConfig{
					Permission: XPermission{
						AllowPermission: "notexistingpermission",
					},
				},
			},
			"/composed/permission/": PathVerbs{
				"get": VerbConfig{
					Permission: XPermission{
						AllowPermission: "very.very.composed.permission",
					},
				},
			},
			"/no-permission": PathVerbs{
				"get":  VerbConfig{},
				"post": VerbConfig{},
			},
			"/with-mongo-find-one": {"get": {Permission: XPermission{AllowPermission: "allow_with_find_one"}}},
		})
	})

	t.Run("request execution fails for invalid URL", func(t *testing.T) {
		url := "http://invalidUrl.com"

		_, err := fetchOpenAPI(url)

		t.Logf("Expected error occurred: %s", err.Error())
		assert.Assert(t, errors.Is(err, ErrRequestFailed), "unexpected error")
	})

	t.Run("request execution fails for invalid URL syntax", func(t *testing.T) {
		url := "	http://url with a tab.com"

		_, err := fetchOpenAPI(url)

		t.Logf("Expected error occurred: %s", err.Error())
		assert.Assert(t, errors.Is(err, ErrRequestFailed), "unexpected error")
	})

	t.Run("request execution fails for unexpected server response", func(t *testing.T) {
		defer gock.Off()

		gock.New("http://localhost:3000").
			Get("/documentation/json").
			Reply(500).
			JSON(map[string]string{"error": "InternalServerError"})

		url := "http://localhost:3000/documentation/json"

		_, err := fetchOpenAPI(url)

		t.Logf("Expected error occurred: %s", err.Error())
		assert.Assert(t, errors.Is(err, ErrRequestFailed), "unexpected error")
	})

	t.Run("request execution fails for unexpected server response", func(t *testing.T) {
		defer gock.Off()

		gock.New("http://localhost:3000").
			Get("/documentation/json").
			Reply(200)

		url := "http://localhost:3000/documentation/json"

		_, err := fetchOpenAPI(url)

		t.Logf("Expected error occurred: %s", err.Error())
		assert.Assert(t, errors.Is(err, ErrRequestFailed), "unexpected error")
	})
}

func TestLoadOASFile(t *testing.T) {
	t.Run("get oas config from file", func(t *testing.T) {
		openAPIFile, err := loadOASFile("./mocks/pathsConfig.json")
		assert.Assert(t, err == nil, "unexpected error")
		assert.Assert(t, openAPIFile != nil, "unexpected nil result")
		assert.DeepEqual(t, openAPIFile.Paths, OpenAPIPaths{
			"/users-from-static-file/": PathVerbs{
				"get": VerbConfig{
					Permission: XPermission{
						AllowPermission: "foobar",
						ResourceFilter: ResourceFilter{
							RowFilter: RowFilterConfiguration{
								HeaderKey: "customHeaderKey",
								Enabled:   true,
							},
						},
					},
				},
				"post": VerbConfig{
					Permission: XPermission{
						AllowPermission: "notexistingpermission",
					},
				},
			},
			"/no-permission-from-static-file": PathVerbs{
				"post": VerbConfig{},
			},
		})
	})

	t.Run("fail for invalid filePath", func(t *testing.T) {
		_, err := loadOASFile("./notExistingFilePath.json")

		t.Logf("Expected error occurred: %s", err.Error())
		assert.Assert(t, err != nil, "failed documentation file read")
	})
}

func TestLoadOAS(t *testing.T) {
	log, _ := test.NewNullLogger()

	t.Run("if TargetServiceOASPath & APIPermissionsFilePath are set together, expect to read oas from static file", func(t *testing.T) {
		envs := config.EnvironmentVariables{
			TargetServiceHost:      "localhost:3000",
			TargetServiceOASPath:   "/documentation/json",
			APIPermissionsFilePath: "./mocks/pathsConfig.json",
		}
		openApiSpec, err := loadOAS(log, envs)
		assert.Assert(t, err == nil, "unexpected error")
		assert.Assert(t, openApiSpec != nil, "unexpected nil result")
		assert.DeepEqual(t, openApiSpec.Paths, OpenAPIPaths{
			"/users-from-static-file/": PathVerbs{
				"get": VerbConfig{
					Permission: XPermission{
						AllowPermission: "foobar",
						ResourceFilter: ResourceFilter{
							RowFilter: RowFilterConfiguration{
								HeaderKey: "customHeaderKey",
								Enabled:   true,
							},
						},
					},
				},
				"post": VerbConfig{
					Permission: XPermission{
						AllowPermission: "notexistingpermission",
					},
				},
			},
			"/no-permission-from-static-file": PathVerbs{
				"post": VerbConfig{},
			},
		})
	})

	t.Run("expect to fetch oasApiSpec from API", func(t *testing.T) {
		envs := config.EnvironmentVariables{
			TargetServiceHost:    "localhost:3000",
			TargetServiceOASPath: "/documentation/json",
		}

		defer gock.Off()
		gock.New("http://localhost:3000").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMock.json")

		openApiSpec, err := loadOAS(log, envs)
		assert.Assert(t, gock.IsDone(), "Mock has not been invoked")
		assert.Assert(t, err == nil, "unexpected error")
		assert.Assert(t, openApiSpec != nil, "unexpected nil result")
		assert.DeepEqual(t, openApiSpec.Paths, OpenAPIPaths{
			"/users/": PathVerbs{
				"get": VerbConfig{
					Permission: XPermission{
						AllowPermission: "foobar",
					},
				},
				"post": VerbConfig{
					Permission: XPermission{
						AllowPermission: "notexistingpermission",
					},
				},
			},
			"/composed/permission/": PathVerbs{
				"get": VerbConfig{
					Permission: XPermission{
						AllowPermission: "very.very.composed.permission",
					},
				},
			},
			"/no-permission": PathVerbs{
				"post": VerbConfig{},
				"get":  VerbConfig{},
			},
			"/with-mongo-find-one": {"get": {Permission: XPermission{AllowPermission: "allow_with_find_one"}}},
		})
	})

	t.Run("expect to throw if TargetServiceOASPath or APIPermissionsFilePath is not set", func(t *testing.T) {
		envs := config.EnvironmentVariables{
			TargetServiceHost: "localhost:3000",
		}
		_, err := loadOAS(log, envs)

		t.Logf("Expected error occurred: %s", err.Error())
		assert.Assert(t, err != nil, fmt.Errorf("missing environment variables one of %s or %s is required", config.TargetServiceOASPathEnvKey, config.APIPermissionsFilePathEnvKey))
	})
}

func TestFindPermission(t *testing.T) {
	t.Run("nested cases", func(t *testing.T) {
		oas := prepareOASFromFile(t, "./mocks/nestedPathsConfig.json")
		OASRouter := oas.PrepareOASRouter()

		found, err := oas.FindPermission(OASRouter, "/not/existing/route", "GET")
		assert.Equal(t, XPermission{}, found)
		assert.Equal(t, err.Error(), "not found oas permission: GET /not/existing/route")

		found, err = oas.FindPermission(OASRouter, "/no/method", "PUT")
		assert.Equal(t, XPermission{}, found)
		assert.Equal(t, err.Error(), "not found oas permission: PUT /no/method")

		found, err = oas.FindPermission(OASRouter, "/use/method/that/not/existing/put", "PUT")
		assert.Equal(t, XPermission{}, found)
		assert.Equal(t, err.Error(), "not found oas permission: PUT /use/method/that/not/existing/put")

		found, err = oas.FindPermission(OASRouter, "/foo/bar/barId", "GET")
		assert.Equal(t, XPermission{
			AllowPermission: "foo_bar_params",
			ResourceFilter: ResourceFilter{
				RowFilter: RowFilterConfiguration{
					HeaderKey: "customHeaderKey",
					Enabled:   true,
				}}},
			found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/foo/bar/barId/another-params-not-configured", "GET")
		assert.Equal(t, XPermission{
			AllowPermission: "foo_bar",
			ResourceFilter: ResourceFilter{
				RowFilter: RowFilterConfiguration{
					HeaderKey: "customHeaderKey",
					Enabled:   true,
				}}},
			found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/foo/bar/nested/case/really/nested", "GET")
		assert.Equal(t, XPermission{AllowPermission: "foo_bar_nested_case"}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/foo/bar/nested", "GET")
		assert.Equal(t, XPermission{
			AllowPermission: "foo_bar_nested",
			ResourceFilter: ResourceFilter{
				RowFilter: RowFilterConfiguration{
					HeaderKey: "customHeaderKey",
					Enabled:   true,
				}}},
			found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/foo/simble", "PATCH")
		assert.Equal(t, XPermission{
			AllowPermission: "foo",
			ResourceFilter: ResourceFilter{
				RowFilter: RowFilterConfiguration{
					HeaderKey: "customHeaderKey",
					Enabled:   true,
				}}},
			found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/test/all", "GET")
		assert.Equal(t, XPermission{}, found)
		assert.Equal(t, err.Error(), "not found oas permission: GET /test/all")

		found, err = oas.FindPermission(OASRouter, "/test/all/", "GET")
		assert.Equal(t, XPermission{AllowPermission: "permission_for_get"}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/test/all/verb", "GET")
		assert.Equal(t, XPermission{AllowPermission: "permission_for_get"}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/test/all/verb", "POST")
		assert.Equal(t, XPermission{AllowPermission: "permission_for_post"}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/test/all/verb", "PUT")
		assert.Equal(t, XPermission{AllowPermission: "permission_for_all"}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/test/all/verb", "PATCH")
		assert.Equal(t, XPermission{AllowPermission: "permission_for_all"}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/test/all/verb", "DELETE")
		assert.Equal(t, XPermission{AllowPermission: "permission_for_all"}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/projects/", "POST")
		assert.Equal(t, XPermission{AllowPermission: "project_all"}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/projects/", "GET")
		assert.Equal(t, XPermission{AllowPermission: "project_get"}, found)
		assert.Equal(t, err, nil)
	})

	t.Run("encoded cases", func(t *testing.T) {
		oas := prepareOASFromFile(t, "./mocks/mockForEncodedTest.json")
		OASRouter := oas.PrepareOASRouter()

		found, err := oas.FindPermission(OASRouter, "/api/backend/projects/5df2260277baff0011fde823/branches/team-james/files/config-extension%252Fcms-backend%252FcmsProperties.json", "POST")
		assert.Equal(t, XPermission{AllowPermission: "allow_commit"}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/api/backend/projects/5df2260277baff0011fde823/branches/team-james/files/config-extension%2Fcms-backend%2FcmsProperties.json", "POST")
		assert.Equal(t, XPermission{AllowPermission: "allow_commit"}, found)
		assert.Equal(t, err, nil)
	})
}

func TestGetXPermission(t *testing.T) {
	t.Run(`GetXPermission fails because no key has been passed`, func(t *testing.T) {
		ctx := context.Background()
		env, err := GetXPermission(ctx)
		require.True(t, err != nil, "An error was expected.")
		t.Logf("Expected error: %s - env: %+v", err.Error(), env)
	})

	t.Run(`GetXPermission returns OPAEvaluator from context`, func(t *testing.T) {
		ctx := context.WithValue(context.Background(), XPermissionKey{}, &XPermission{AllowPermission: "foo"})
		permission, err := GetXPermission(ctx)
		require.True(t, err == nil, "Unexpected error.")
		require.True(t, permission != nil, "XPermission not found.")
	})
}
