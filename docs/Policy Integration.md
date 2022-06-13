# How to write a policy

Since policies are executed with [OpenPolicy Agent](https://www.openpolicyagent.org) they must be written in the [Rego language](https://www.openpolicyagent.org/docs/latest/policy-reference/).

The whole set of Rego capabilities is supported, in addition to that Rönd provides a set of custom built-ins.

## Rego input

Policies will receive a specifically crafted `input` object with information concerning the request; the `input` object is shaped as follows:

```json
{
  "request": {
    "method":  String,
    "path":    String,
    "headers": Object {
      String: Array[String]
    },
    "pathParams": Object,
    "query":   Object {
      String: Array[String]
    },
    "body": Object
  },
  "response": {
    "body": Object
  },
  "user": {
    "properties": Object{
      // this object contains the user properties specified in the header provided with the `USER_PROPERTIES_HEADER_KEY`
    },
    "groups": Array[String], // list of strings provided in the `USER_GROUPS_HEADER_KEY`
    "bindings": Array[Binding], // only provided if MongoDB configuration is set
    "roles": Array[Role], // only provided if MongoDB configuration is set
    "resourcePermissionsMap": Object{} // Created only for APIs with `option.enableResourcePermissionsMapOptimization` enabled
  },
  "clientType": String
}
```

> The request body in the input object is only provided if the request method is either `POST`, `PUT`, `DELETE`  or `PATCH` and the request Content Type is `application/json`.


### Regarding resourcePermissionsMap

Some policies, especially the one that needs to perform time consuming tasks on the response body may take a while to be processed. Since iterating over user bindings, roles and permissions may be time consuming you can use the `resourcePermissionsMap` to verify user permissions in constant time. 

The `resourcePermissionsMap` is a map containing a set of key/value pairs in which the key is composed as `permissionId:resourceType:resourceId` and the value is always set to `true`.  
Please be careful: since creating the map still requires some computations to be performend over the user bindings; you may not perceive any optimization benefit from using the feature if the Rego policy is already fast. Enable the feature only when necessary to avoid useless computations to be performed.  


## RBAC Data model

When the variables `MONGODB_URL`, `ROLES_COLLECTION_NAME` and `BINDINGS_COLLECTION_NAME` are set Rönd will perform a check over the user permission. These permissions, in the form of Roles and Bindings are then provided in the `input` object, in this way your policy can operate according to your needs based on user actual permissions.


> If `MONGODB_URL` variable is set then the envs  `ROLES_COLLECTION_NAME` and `BINDINGS_COLLECTION_NAME` are required.


The binding object is composed as follow:
```json
{
  "bindingId":    String,
  "groups":       Array[String],
  "subjects":     Array[String],
  "permissions":  Array[String],
  "roles":        Array[String],
  "resource":     Object { 
    "resourceType": String,
    "resourceId":   String
  },
  "__STATE__":     String
} 
```

While the role one is composed as follows:

```json
{
  "roleId":       String,
  "permissions":  Array[String],
  "__STATE__:     String
} 
```

## Custom Built-ins

### get_header

Since headers keys are transformed in canonical form (i.e. "x-api-key" become "X-Api-Key") by Go, in order to allow accessing them in case-insensitive mode, you can use our built-in function [`get_header`](#get_header-built-in-function)

```
output := get_header(headerKey: String, headers: Map[String]Array<String>) 
```

The returned output is the first header value present in the `headers` map at key `headerKey`. If `headerKey` doesn't exist the output returned is an empty string.

Without the built-in you have to access headers in canonical form

```go
package policies

default api_key = false

api_key {
  count(input.request.headers["X-Api-Key"]) != 0
}
```

however with the `get_header` function you can write the header name as you prefer:

```go
package policies

default api_key = false
api_key {
  get_header("x-api-key", input.request.headers) != ""
}
```

### find_one 

The `find_one` built-in function can be used to fetch data from a MongoDB collection, it accepts the collection name and a custom query and returns the document that matches the query using the `FindOne` MongoDB API.

Example usage to fetch a rider from the `riders` collection by using the rider identifier provided in the request path parameters:

```rego
riderId := input.request.pathParams.riderId
rider := find_one("riders", { "riderId": riderId })
rider.available == true
```

### find_many

The `find_many` built-in function can be used to fetch multiple data from a MongoDB collection, it accepts the collection name and a custom query and returns the documents that match the query using the `Find` MongoDB API.

Example usage to fetch a rider from the `riders` collection by using the rider identifier provided in the request path parameters:

```rego
riders := find_many("riders", { "available": true })
rider := riders[_]
rider.riderId == input.request.pathParams.riderId
```
