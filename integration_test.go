package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/testutils"
	"github.com/rond-authz/rond/openapi"

	"github.com/caarlos0/env/v11"
	"github.com/fredmaggiowski/gowq"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"
)

func BenchmarkStartup(b *testing.B) {
	b.StopTimer()

	tmpdir, err := os.MkdirTemp("", "rond-bench-")
	require.NoError(b, err)
	oasFileName, policiesFileName := generateAndSaveConfig(b, tmpdir, 100)
	b.Logf("Files generated in %s", tmpdir)
	defer func() {
		b.Logf("Removing tmpdir %s", tmpdir)
		os.RemoveAll(tmpdir)
	}()

	log, _ := test.NewNullLogger()
	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = testutils.LocalhostMongoDB
		b.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}
	randomizedDBNamePart := testutils.GetRandomName(10)
	mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

	defer gock.Off()
	defer gock.DisableNetworkingFilters()
	defer gock.DisableNetworking()
	gock.EnableNetworking()
	gock.NetworkingFilter(func(r *http.Request) bool {
		if r.URL.Path == "/documentation/json" && r.URL.Host == "localhost:3040" {
			return false
		}
		return true
	})

	gock.New("http://localhost:3040").
		Persist().
		Get("/documentation/json").
		Reply(200).
		File(oasFileName)

	envs, err := env.ParseAsWithOptions[config.EnvironmentVariables](env.Options{
		Environment: map[string]string{
			"TARGET_SERVICE_HOST":      "localhost:3040",
			"TARGET_SERVICE_OAS_PATH":  "/documentation/json",
			"OPA_MODULES_DIRECTORY":    policiesFileName,
			"LOG_LEVEL":                "fatal",
			"MONGODB_URL":              fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName),
			"BINDINGS_COLLECTION_NAME": "bindings",
			"ROLES_COLLECTION_NAME":    "roles",
		},
	})
	require.NoError(b, err)

	for n := 0; n < b.N; n++ {
		b.StartTimer()
		data, err := setupService(envs, log)
		require.True(b, <-data.sdkBootState.IsReadyChan())
		b.StopTimer()

		data.close()
		require.NoError(b, err)
	}
}

func TestStartupAndLoadWithConcurrentRequests(t *testing.T) {
	log, _ := test.NewNullLogger()

	tmpdir, err := os.MkdirTemp("", "rond-startup-test-")
	require.NoError(t, err)

	policies := []string{`package policies`}
	policies = append(policies, `allow_get {
	verb := input.request.method
	verb == "GET"
}`)
	policies = append(policies, `allow_post {
	verb := input.request.method
	verb == "POST"
}`)
	policies = append(policies, generateFilterPolicy("something")) // filter_something
	policies = append(policies, generateProjectionPolicy("data"))  // proj_data

	oas := &openapi.OpenAPISpec{
		Paths: map[string]openapi.PathVerbs{
			"/allow-get": {
				http.MethodGet: {
					PermissionV2: &core.RondConfig{
						RequestFlow: core.RequestFlow{PolicyName: "allow_get"},
					},
				},
				http.MethodPost: {
					PermissionV2: &core.RondConfig{
						RequestFlow: core.RequestFlow{PolicyName: "allow_get"},
					},
				},
			},
			"/filter-something": {
				http.MethodGet: {
					PermissionV2: &core.RondConfig{
						RequestFlow: core.RequestFlow{PolicyName: "filter_something", GenerateQuery: true},
					},
				},
			},
			"/project-data": {
				http.MethodPost: {
					PermissionV2: &core.RondConfig{
						RequestFlow:  core.RequestFlow{PolicyName: "allow_post"},
						ResponseFlow: core.ResponseFlow{PolicyName: "proj_data"},
					},
				},
			},
		},
	}
	oasFileName := writeOAS(t, tmpdir, oas)
	policiesFileName := writePolicies(t, tmpdir, policies)

	defer gock.Off()
	defer gock.DisableNetworkingFilters()
	defer gock.DisableNetworking()

	gock.EnableNetworking()
	gock.NetworkingFilter(func(r *http.Request) bool {
		if r.URL.Host == "localhost:3050" {
			return false
		}
		if r.URL.Path == "/documentation/json" && r.URL.Host == "localhost:3050" {
			return false
		}
		return true
	})

	gock.New("http://localhost:3050").
		Persist().
		Get("/documentation/json").
		Reply(200).
		File(oasFileName)

	gock.New("http://localhost:3050/").
		Persist().
		Get("/allow-get").
		Reply(200)
	gock.New("http://localhost:3050/").
		Persist().
		Get("/filter-something").
		Reply(200)
	gock.New("http://localhost:3050/").
		Persist().
		Post("/project-data").
		Reply(200).
		JSON([]string{})

	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = testutils.LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}
	randomizedDBNamePart := testutils.GetRandomName(10)
	mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)
	envs, err := env.ParseAsWithOptions[config.EnvironmentVariables](env.Options{
		Environment: map[string]string{
			"TARGET_SERVICE_HOST":      "localhost:3050",
			"TARGET_SERVICE_OAS_PATH":  "/documentation/json",
			"OPA_MODULES_DIRECTORY":    policiesFileName,
			"LOG_LEVEL":                "fatal",
			"MONGODB_URL":              fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName),
			"BINDINGS_COLLECTION_NAME": "bindings",
			"ROLES_COLLECTION_NAME":    "roles",
		},
	})
	require.NoError(t, err)

	app, err := setupService(envs, log)
	require.NoError(t, err)
	require.True(t, <-app.sdkBootState.IsReadyChan())
	defer app.close()

	// everything is up and running, now start bombarding the webserver
	type RequestConf struct {
		Verb           string
		Path           string
		ExpectedStatus int
	}
	dictionary := []RequestConf{
		{Verb: http.MethodGet, Path: "/allow-get", ExpectedStatus: http.StatusOK},
		{Verb: http.MethodPost, Path: "/allow-get", ExpectedStatus: http.StatusForbidden},
		{Verb: http.MethodGet, Path: "/filter-something", ExpectedStatus: http.StatusOK},
		{Verb: http.MethodPost, Path: "/filter-something", ExpectedStatus: http.StatusNotFound},
		{Verb: http.MethodPost, Path: "/project-data", ExpectedStatus: http.StatusOK},
		{Verb: http.MethodGet, Path: "/project-data", ExpectedStatus: http.StatusNotFound},
	}

	queue := gowq.New[RequestConf](100)

	i := 0
	for i < 100_000 {
		d := dictionary[i%len(dictionary)]
		i++
		queue.Push(func(ctx context.Context) (RequestConf, error) {
			w := httptest.NewRecorder()

			req := httptest.NewRequest(d.Verb, d.Path, nil)
			app.router.ServeHTTP(w, req)
			require.Equal(t, d.ExpectedStatus, w.Result().StatusCode)

			return d, nil
		})
	}

	_, errors := queue.RunAll(context.TODO())
	require.Len(t, errors, 0)
}

func writeOAS(t require.TestingT, tmpdir string, oas *openapi.OpenAPISpec) string {
	oasContent, err := json.Marshal(oas)
	require.NoError(t, err)

	oasFileName := fmt.Sprintf("%s/oas.json", tmpdir)
	err = os.WriteFile(oasFileName, oasContent, 0644)
	require.NoError(t, err)
	return oasFileName
}

func writePolicies(t require.TestingT, tmpdir string, policies []string) string {
	policyFileName := fmt.Sprintf("%s/policies.rego", tmpdir)
	policiesContent := []byte(strings.Join(policies, "\n"))
	err := os.WriteFile(policyFileName, policiesContent, 0644)
	require.NoError(t, err)
	return policyFileName
}

func generateAndSaveConfig(t require.TestingT, tmpdir string, numberOfPaths int) (string, string) {
	oas := &openapi.OpenAPISpec{
		Paths: make(map[string]openapi.PathVerbs),
	}
	policies := []string{"package policies"}

	for i := 0; i < numberOfPaths; i++ {
		randomName := testutils.GetRandomName(10)
		filterPolicy := generateFilterPolicy(randomName)
		allowPolicy := generateAllowPolicy(randomName)
		projPolicy := generateProjectionPolicy(randomName)
		builtinPolicy := generateCustomBuiltinPolicy(randomName)

		policies = append(policies, filterPolicy, allowPolicy, projPolicy, builtinPolicy)

		pathName := fmt.Sprintf("/path-%d-%s", i, randomName)

		oas.Paths[pathName] = openapi.PathVerbs{
			http.MethodGet: openapi.VerbConfig{
				PermissionV2: &core.RondConfig{
					RequestFlow: core.RequestFlow{
						PolicyName:    fmt.Sprintf("filter_%s", randomName),
						GenerateQuery: true,
					},
					ResponseFlow: core.ResponseFlow{
						PolicyName: fmt.Sprintf("proj_%s", randomName),
					},
					Options: core.PermissionOptions{
						IgnoreTrailingSlash: true,
					},
				},
			},
			http.MethodPost: openapi.VerbConfig{
				PermissionV2: &core.RondConfig{
					RequestFlow: core.RequestFlow{
						PolicyName: fmt.Sprintf("allow_%s", randomName),
					},
					Options: core.PermissionOptions{
						IgnoreTrailingSlash: true,
					},
				},
			},
			http.MethodDelete: openapi.VerbConfig{
				PermissionV2: &core.RondConfig{
					RequestFlow: core.RequestFlow{
						PolicyName: fmt.Sprintf("builtin_%s", randomName),
					},
					Options: core.PermissionOptions{
						IgnoreTrailingSlash: true,
					},
				},
			},
		}
	}

	oasFileName := writeOAS(t, tmpdir, oas)
	policyFileName := writePolicies(t, tmpdir, policies)

	return oasFileName, policyFileName
}

func generateFilterPolicy(name string) string {
	return fmt.Sprintf(`filter_%s {
	filter := data.resources[_]
	filter.key == 42
}`, name)
}

func generateProjectionPolicy(name string) string {
	return fmt.Sprintf(`proj_%s [projects] {
    projects := [projects_with_envs_filtered |
        project := input.response.body[_]
        projects_with_envs_filtered := project
    ]
	}`, name)
}

func generateAllowPolicy(name string) string {
	return fmt.Sprintf(`allow_%s {
  true
}`, name)
}

func generateCustomBuiltinPolicy(name string) string {
	return fmt.Sprintf(`builtin_%s {
	get_header("type", input.headers) == "single"

	projectId := input.request.pathParams.projectId
	project := find_one("projects", {"projectId": projectId})
	true
	project.tenantId == "some-tenant"
} {
	get_header("type", input.headers) == "multiple"

	projectId := input.request.pathParams.projectId
	projects := find_many("projects", {"$or": [{"projectId": projectId}, {"projectId": "some-project2"}]})
	count(projects) == 2

	projects[0].tenantId == "some-tenant"
	projects[1].tenantId == "some-tenant2"
}
`, name)
}
