package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
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
			"/no-permission": PathVerbs{
				"post": VerbConfig{},
			},
		})
	})

	t.Run("request execution fails for invalid URL", func(t *testing.T) {
		url := "http://invalidUrl.com"

		_, err := fetchOpenAPI(url)

		t.Logf("Expected error occured: %s", err.Error())
		assert.Assert(t, errors.Is(err, ErrRequestFailed), "unexpected error")
	})

	t.Run("request execution fails for invalid URL syntax", func(t *testing.T) {
		url := "	http://url with a tab.com"

		_, err := fetchOpenAPI(url)

		t.Logf("Expected error occured: %s", err.Error())
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

		t.Logf("Expected error occured: %s", err.Error())
		assert.Assert(t, errors.Is(err, ErrRequestFailed), "unexpected error")
	})

	t.Run("request execution fails for unexpected server response", func(t *testing.T) {
		defer gock.Off()

		gock.New("http://localhost:3000").
			Get("/documentation/json").
			Reply(200)

		url := "http://localhost:3000/documentation/json"

		_, err := fetchOpenAPI(url)

		t.Logf("Expected error occured: %s", err.Error())
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

		t.Logf("Expected error occured: %s", err.Error())
		assert.Assert(t, err != nil, "failed documentation file read")
	})
}

func TestLoadOAS(t *testing.T) {
	log, _ := test.NewNullLogger()

	t.Run("if TargetServiceOASPath & APIPermissionsFilePath are set together, expect to read oas from static file", func(t *testing.T) {
		envs := EnvironmentVariables{
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
		envs := EnvironmentVariables{
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
			"/no-permission": PathVerbs{
				"post": VerbConfig{},
			},
		})
	})

	t.Run("expect to throw if TargetServiceOASPath or APIPermissionsFilePath is set", func(t *testing.T) {
		envs := EnvironmentVariables{
			TargetServiceHost: "localhost:3000",
		}
		_, err := loadOAS(log, envs)

		t.Logf("Expected error occured: %s", err.Error())
		assert.Assert(t, err != nil, fmt.Errorf("missing environment variables one of %s or %s is required", TargetServiceOASPathEnvKey, APIPermissionsFilePathEnvKey))
	})
}
