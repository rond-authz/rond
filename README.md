

<div align="center">

  <img alt="Rönd Logo" src="https://github.com/rond-authz/.github/blob/58bf35733bb43143cfb6ad9b05b93e20d6729633/profile/img/Rond_Logo_Full-Lockup_Horizontal.png#gh-light-mode-only" width="300" />
  <img alt="Rönd Logo" src="https://github.com/rond-authz/.github/blob/58bf35733bb43143cfb6ad9b05b93e20d6729633/profile/img/Rond_Logo_Full-Lockup_Horizontal-White.png#gh-dark-mode-only"  width="300">
  <br/><br/>
  
[![Build Status][github-actions-svg]][github-actions]
[![Coverage Status][coverall-svg]][coverall-io]
[![Go Report Card][go-report-card-badge]][go-report-card]
[![Go Sec][security-badge-svg]][security-badge]

[![Mia-Platform][mia-platform-badge]][mia-platform]

# Rönd

Rönd is a lightweight container that distributes security policy enforcement throughout your application.
</div>

Rönd is based on [OpenPolicy Agent](https://www.openpolicyagent.org) and allows you to define security policies to be executed during API invocations. Rönd runs in your Kubernetes cluster as a sidecar container of your Pods.
Rönd intercepts the API traffic, applies your policies and, based on the policy result, forwards the request to your application service or rejects the API invocation.

## Why Rönd?

Find out more [here][why-rond].

## Features

Rönd supports three policy types:

1. Allow or reject request
2. Query generation during the request flow
3. Response body patching

## RBAC capabilities

Rönd natively allows you to build an RBAC solution based on Roles and Bindings saved in MongoDB.

## Local development

### Run tests

```sh
make test
```

Please note that in order to run tests you need Docker to be installed, since tests need a local instance of MongoDB to be up and running `make tests` takes care of it by creating a new `mongo` container.

### Contributing

Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for further details about the process for submitting pull requests.

[github-actions]: https://github.com/rond-authz/rond/actions/workflows/test.yml
[github-actions-svg]: https://github.com/rond-authz/rond/actions/workflows/test.yml/badge.svg
[coverall-svg]: https://coveralls.io/repos/github/rond-authz/rond/badge.svg
[coverall-io]: https://coveralls.io/github/rond-authz/rond
[security-badge-svg]: https://github.com/rond-authz/rond/actions/workflows/security.yml/badge.svg
[security-badge]: https://github.com/rond-authz/rond/actions/workflows/security.yml
[go-report-card-badge]: https://goreportcard.com/badge/github.com/rond-authz/rond
[go-report-card]: https://goreportcard.com/report/github.com/rond-authz/rond
[mia-platform-badge]: https://img.shields.io/badge/Supported%20by-Mia--Platform-green?style=for-the-badge&link=https://mia-platform.eu/&color=3d86f4&labelColor=214147
[mia-platform]: https://mia-platform.eu/?utm_source=referral&utm_medium=github&utm_campaign=rond
[why-rond]: https://github.com/rond-authz#why-r%C3%B6nd
