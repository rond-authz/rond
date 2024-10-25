package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/caarlos0/env/v11"
	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/testutils"
	"github.com/rond-authz/rond/openapi"
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

func generateAndSaveConfig(t require.TestingT, tmpdir string, numberOfPaths int) (string, string) {
	oas := openapi.OpenAPISpec{
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

	oasContent, err := json.Marshal(oas)
	require.NoError(t, err)

	oasFileName := fmt.Sprintf("%s/oas.json", tmpdir)
	err = os.WriteFile(oasFileName, oasContent, 0644)
	require.NoError(t, err)

	policyFileName := fmt.Sprintf("%s/policies.rego", tmpdir)
	policiesContent := []byte(strings.Join(policies, "\n"))
	err = os.WriteFile(policyFileName, policiesContent, 0644)
	require.NoError(t, err)

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
