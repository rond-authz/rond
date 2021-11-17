# How to configure your RBAC service

The concept behind this service is proxy the incoming request and check permissions.
To setup correctly this service you need to follow this steps

## 1) Environment variables

| name | type | default value | required | description |
| ---- | ---- | ------------- | -------- | ----------- |
| LOG_LEVEL | string | info | - | one of["info", "trace", "debug", "warning", "error"] |
| HTTP_PORT | string | 8080 | - | service port to expose service |
| TARGET_SERVICE_HOST | string | - | ✅ | target service to redirect  | 
| API_PERMISSIONS_FILE_PATH | string | - | - | file path where you can manually configure permissions for your API, this substitues the automatic documentation fetch performed by the service. [See the example](#api-permission-file) |
| TARGET_SERVICE_OAS_PATH | string | - | - | endpoint of sibling container to contact for retrieve schemas (es. localhost:3001) |
| OPA_MODULES_DIRECTORY | string | - | ✅ | folder path where you serve all opa module. this files will be used to evaluate policy. [See the example](#rego-example) |
| DELAY_SHUTDOWN_SECONDS | int | 10 (seconds) | - | the sidecar graceful shutdown |


### Rego example
```
    package example

    default foo = false

    foo {
        count(input.request.headers["X-Backdoor"]) != 0
    }
```

### API permission file

```json
{
    "paths": {
         "/hello": {
            "get": {
                "x-permission": {
                    "allow": "foo"
                }
            }
        }
    }
}
```
