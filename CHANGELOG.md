# CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

## 1.1.1 - 04/05/2022

- [JCE-175](https://makeitapp.atlassian.net/JCE-175): fixed unwanted behaviour to handle path paramenter with slash escaped character `%2F`

## 1.1.0 - 03/05/2022

### Added

- [RJMR-209](https://makeitapp.atlassian.net/RJMR-209): if the option `permissionsOnResourceMapEnabled` is set at true in the XPermission inside the input provided to the opa evaluator will be present a new object `PermissionsOnResurceMap`containing set of key/value pairs in which the key is composed as `permissionId:resoruceType:resourceId` and the value is always set to `true`

## 1.0.1 - 22/04/2022

### Fixed

- fix print statement output

## 1.0.0 - 15/04/2022

### Added

- print statement available with `LOG_LEVEL="trace"`

## 0.8.3 - 29/03/2022

### Added

- [MCRDMPE22-113](https://makeitapp.atlassian.net/MCRDMPE22-113): Added method delete to insert body request in rego input

## 0.8.2 - 21/03/2022

### Fixed

- Prevent status routes to run into the OPA Middleware 

## 0.8.1 - 14/03/2022

### Update

- glogger v2.1.3 that implements `http.Flusher` interface, useful to fix flushing behavior in reverse proxy for streaming APIs

### Fixed

- [JMRBA-100](https://makeitapp.atlassian.net/JMRBA-100): set reverse proxy flush interval to -1 to fix issues with streaming APIs passing through the container
- Fixed fallback path registration

## 0.8.0 - 08/03/2022

### Added

 - [JAP-1](https://makeitapp.atlassian.net/browse/JAP-2): Added `/grant/bindings/resource/{resourceType}` api to handle the grant of a user role on a single resource
 - [JAP-2](https://makeitapp.atlassian.net/browse/JAP-2): Added `/revoke/bindings/resource/{resourceType}` api to handle the revoke of a user role on a set resources

## 0.7.0 - 02/03/2022

### Fixed

 - [JAF-310](https://makeitapp.atlassian.net/browse/JAF-310): prevent response policy evaluation if API invocation has a status code outside the [200,299] range

### Added

- [RJMR-177](https://makeitapp.atlassian.net/browse/RJMR-177): RBAC now supports standalone mode. The new mode can be set up with the use of `STANDALONE` and `PATH_PREFIX_STANDALONE` environment variables

## 0.6.0 - 17/02/2022

### Changed

- [JAF-278](https://makeitapp.atlassian.net/browse/JAF-278): optimized query evaluation with precomputed evaluators

### Fixed

- provide `application/json` Content-Type header when sending error responses
- response policy proper evaluation when the same API has also a request filter policy

## 0.5.0 - 07/02/2022

### Added

- added support for `find_many` builtin in Rego policies

## 0.4.0 - 01/02/2022

### Added

- [JAF-231](https://makeitapp.atlassian.net/browse/JAF-231): added support for `find_one` builtin in Rego policies

## 0.3.1 - 31/01/2022

### Changed

- [JAF-235](https://makeitapp.atlassian.net/browse/JAF-235): when the filter row query is empty and content-type is application json, the rbac handler return empty array

### Fixed

- supporting OAS with brackets params notation in internal policy resolver

## 0.3.0 - 25/01/2022

### Changed

- [JAF-182](https://makeitapp.atlassian.net/browse/JAF-182): Implemented column filtering on response body base on policy evaluation
- refactor: User struct now contains userBindings and Roles
- If no userId header is provided now mongo is not called in order to retrive user bindings and roles.

### Added

- [JAF-205](https://makeitapp.atlassian.net/browse/JAF-205): Added `pathParameter` to rego input request.
- [JAF-205](https://makeitapp.atlassian.net/browse/JAF-205): routes sorting during registration to prevent pathParams retrieval error
- [JAF-233](https://makeitapp.atlassian.net/browse/JAF-233): better business errors for policies evaluation
- [JAF-215](https://makeitapp.atlassian.net/browse/JAF-215): support body serialization in Rego input for specific content type and methods
- [JAF-226](https://makeitapp.atlassian.net/browse/JAF-226): Removed limitation to dashed routes

## 0.2.0 - 14/01/2022

### Changed

- refactored rowFiltering data structure

### Added

- [JAF-126](https://makeitapp.atlassian.net/browse/JAF-126): Added resource field in binding struct.
- [JAF-156](https://makeitapp.atlassian.net/browse/JAF-156): support the method all in the manual routes oas file
- [JAF-135](https://makeitapp.atlassian.net/browse/JAF-135): rbac service now support row filtering query for mongo forwarded in a custom header to the requested service
- [JAF-145](https://makeitapp.atlassian.net/browse/JAF-145): handle path prefix for manual route
- [JAF-133](https://makeitapp.atlassian.net/browse/JAF-133): documentation route handled correctly

### BREAKING

- [JAF-152](https://makeitapp.atlassian.net/browse/JAF-152): bindings and roles are now given as input to the OPA evaluator. The old check on user permission is no more performed and the entire ownership is given to rego

### Updated

- OPA v0.36.0

## 0.1.0 - 17/12/2021

### Changed

- [JAF-89](https://makeitapp.atlassian.net/browse/JAF-89): Convert API path with variables according the gorilla mux requirements
- [JAF-103](https://makeitapp.atlassian.net/browse/JAF-103): Support dot character as divider in the x-permission string, replaced as underscore for rego policy query
- [JAF-116](https://makeitapp.atlassian.net/browse/JAF-116): ignoring healthiness routes when defining proxied routes

### Added

- [JAF-100](https://makeitapp.atlassian.net/browse/JAF-100): Added the check on user permission before evaluating the query
- [JAF-98](https://makeitapp.atlassian.net/browse/JAF-98): Added the user infos in the input rego
- [JAF-99](https://makeitapp.atlassian.net/browse/JAF-99): mongodb integrated to load roles and bindings collections
- [JAF-45](https://makeitapp.atlassian.net/browse/JAF-45): Created get_header custom built-in rego function
- [JAF-46](https://makeitapp.atlassian.net/browse/JAF-46): Added support for the target service documentation API, with a evaluation skip if is set targetServiceOASPath env
- [JAF-39](https://makeitapp.atlassian.net/browse/JAF-39): Support API permission specification from file
- [JAF-27](https://makeitapp.atlassian.net/browse/JAF-27): OPA integration with single module loading and handler validation
- [JAF-23](https://makeitapp.atlassian.net/browse/JAF-23): rbac service initial configuration from openApi specifications
