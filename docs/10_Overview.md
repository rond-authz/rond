# RBAC service

The RBAC Service is responsible for handling permissions, useful to restrict access to specific resources, based on the Roles of individual users within an organization. RBAC ensures that users can only access the information they are allowed to, preventing anyone from accessing information that doesn't pertain to them.

:::info
The RBAC Service is thought to be deployed as a sidecar container for each custom service that needs RBAC.
:::

RBAC sidecar will expose all the routes exposed by the custom services in the documentation route under the OpenAPI 3 specification. The service will proxy them to the original destination applying some rules based on the permission of the user expressed inside the bindings.

When the variables `MONGODB_URL`, `ROLES_COLLECTION_NAME` and `BINDINGS_COLLECTION_NAME` are set the RBAC Service will perform a check over the user permission taking them form the collection specified in the variables above. If the user does not have the required allow permission for a request the service will respond with a 403 Forbidden status code.

:::caution
If `MONGODB_URL` variable is set then the envs  `ROLES_COLLECTION_NAME` and `BINDINGS_COLLECTION_NAME` becomes required and the service will respond 500 to any request received.
:::

:::info
Any API invocation to the path matching the one provided as `TARGET_SERVICE_OAS_PATH` with method `GET` will always be proxied to the target service unless the given OpenAPI Specification provides the path with a custom policy configuration, in this case the API will be proxied only if the policy evaluates successfully.
:::
