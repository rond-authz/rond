# CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

### Added

- [JAF-133](https://makeitapp.atlassian.net/browse/JAF-133): handle path prefix for manual route

### BREAKING

- [JAF-152](https://makeitapp.atlassian.net/browse/JAF-152): bindings and roles are now given as input to the OPA evaluator. The old check on user permission is no more performed and the entire ownership is given to rego

## 1.0.0 - 17/12/2021

### Changes

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
