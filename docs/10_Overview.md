# RBAC service

The RBAC Service is responsible for handling permissions, useful to restrict access to specific resources, based on the Roles of individual users within an organization. RBAC ensures that users can only access the information they are allowed to, preventing anyone from accessing information that doesn't pertain to them.

:::info
The RBAC Service is thought to be deployed as a sidecar container for each custom service that needs RBAC.
:::

RBAC sidecar will expose all the routes exposed by the custom services in the documentation route under the OpenAPI 3 specification. The service will proxy them to the original destination applying some rules based on the permission of the user expressed inside the bindings.
