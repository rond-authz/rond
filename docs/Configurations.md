# Rönd configuration

To correctly setup the container you need to provide a few configurations; some configurations are provided as environment variables, while others are provided via configuration files.

## Environment variables

| name | type | default value | required | description |
| ---- | ---- | ------------- | -------- | ----------- |
| `LOG_LEVEL` | `string` | _info_ | - | one of "_info_", "_trace_", "_debug_", "_warning_", "_error_" |
| `HTTP_PORT` | `string` | **8080** | - | port to expose the API service |
| `STANDALONE` | `boolean` | `false` | - | defines whether the service is running as a sidecar or in standalone mode |
| `TARGET_SERVICE_HOST` | `string` | - | if `STANDALONE` is `false` | the host of target service to redirect the traffic when authorization rules are passed | 
| `TARGET_SERVICE_OAS_PATH` | `string` | - | if `STANDALONE` is `false` | endpoint path of sibling container to contact for retrieving the OAS definition (es. `/documentation/json`) |
| `API_PERMISSIONS_FILE_PATH` | `string` | - | - | file for manual configuration of the OAS; this substitutes the automatic documentation fetch performed by the service towards `API_ERMISSIONS_FILE_PATH`. [See the example](#api-permission-file) |
| `OPA_MODULES_DIRECTORY` | `string` | - | ✅ | folder path where are provided the Rego files for OPA rules evaluation; these files will be used to evaluate policy. [See the example](#rego-examples) |
| `USER_PROPERTIES_HEADER_KEY` | `string` | `miauserproperties` | - | header name for the optional header that contains the user properties |
| `USER_GROUPS_HEADER_KEY` | `string` | `miausergroups` | - | header name for the optional header that contains the user groups |
| `CLIENT_TYPE_HEADER_KEY` | `string` | `client-type` | - | header name for the optional header that contains a client type identifier |
| `MONGODB_URL`| `string`| - | - | url to connect to a MongoDB instance (useful for RBAC data retrieval and `find_` Rego built-ins) |
| `ROLES_COLLECTION_NAME` | `string` | - | if `MONGODB_URL` is set | name of the role collection |
| `BINDINGS_COLLECTION_NAME` | `string` | - | if `MONGODB_URL` is set | name of the bindings collection |
| `PATH_PREFIX_STANDALONE` | `string` | `/eval` | - | when in standalone mode, this variables configures the prefix for all validation APIs defined by the OAS |
| `DELAY_SHUTDOWN_SECONDS` | `int` | **10** | - | seconds to delay forced server stop, useful for graceful shutdown |

## Configuration files

Rönd accepts two configuration files, one containing the OpenPolicy Agent Rego policies (required) and an otional file for OpenAPI Specification details.

### OpenPolicy Agent policies

The `.rego` file must be provided inside the directory specified with the `OPA_MODULES_DIRECTORY` environment variable; right now a single file is supported so the first `.rego` file found will be used for policy evaluation.

### OpenAPI Specification file

The OpenAPI Specification file is required only when the `TARGET_SERVICE_OAS_PATH` variable is not provided; it specifies the API that are exposed by your service and thus must be authorized with specific policies.

#### Specify API permissions

In order to define the Rego policies to be evaluated for the API to be authorized you must define the custom attribute `x-permission` in your OAS schema.

The x-permission attribute is shaped as an object with the following properties:

- `allow` **(string, required)**: the name of the Rego policy that should be executed upon the API invocation
- `options`  **(object)**:
  - `enableResourcePermissionsMapOptimization` **(boolean)**: flag to enable the generation of an optimized map of user permissions (useful when performing RBAC logics); more information in the [Policy Integration page](./Policy%20Integration.md);
- `resourceFilter` **(object)**: object representing information on what resource the API is looking for to perform filtering operations:
  - `rowFilter` **(object)**: this object contains all the configurations needed to perform filtering operation on rows:
    - `enabled` **(bool)**:  activation value for row filtering
    - `headerName` **(string)**: identifier of the header sent to the requested service in which the interpolated query will be injected. The default values is `acl_rows`.
- `responseFilter` **(object)**: this object contains all the configurations needed to perform filtering operation on response: 
  - `policy`: the name of the Rego policy that should be executed upon the API invocation.

> Please note that any API that is not specified is immediately blocked.

For example, if you want the `greetings_read` policy to be evaluated when invoking the `GET /hello` API your custom service must define its API documentation as follows:

```json
{
    "paths": {
        "/hello": {
            "get": {
                "x-permission": {
                    "allow": "greetings_read"
                }
            }
        }
    }
}
```

If you want to generate a query you can enable the `resourceFilter` option; with this option you can enable query generation, 
which will change the way the `allow` policy is threated, allowing you to write a policy that returns 
a query that is then forwarded to the application service using the header specified with the `headerName` option. 

```json
{
    "paths": {
        "/hello": {
            "get": {
                "x-permission": {
                    "allow": "greetings_read",
                    "resourceFilter": {
                        "rowFilter": {
                          "enabled": true,
                          "headerName": "x-acl-rows"
                        }
                    }
                }
            }
        }
    }
}
```

If you need to modify the response payload you can add the `responseFilter` field; with the configuration below 
the `greetings_read` policy will be evaluated before contacting the application service;
when the application service sends its response, the `filter_response_example` policy will be evaluated and its result will be used as the new response body.

```json
{
    "paths": {
        "/hello": {
            "get": {
                "x-permission": {
                    "allow": "greetings_read",
                    "responseFilter": {
                      "policy": "filter_response_example"
                    }
                }
            }
        }
    }
}
```


> Any API invocation to the path matching the one provided as `TARGET_SERVICE_OAS_PATH` with method `GET` will always be proxied to the target service unless the given OpenAPI Specification provides the path with a custom policy configuration, in this case the API will be proxied only if the policy evaluates successfully.


### Rego package

In order to execute policy a valuation, a Rego package file is required, you have to provide it inside the directory specified with the `OPA_MODULES_DIRECTORY` environment variable.

Please be careful since the package **must** be named `policies`, so the rego file must start with

```go
package policies
```

## Standalone mode

Rönd can run in standalone mode, to enable it jnust set the `STANDALONE` environment variable to `true`. When this mode is active the Rönd will expose the APIs defined in the provided OAS under the `PATH_PREFIX_STANDALONE` environment variable.
