package main

import (
	"errors"
	"testing"

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
