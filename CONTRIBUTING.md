# Contribution Guidelines

First off, thank you for considering contributing to this project.

Please follow these guidelines for helping us to better address your issue, assessing changes, and helping you finalize your pull requests.
There are many ways to contribute, from writing examples, improving the documentation, submitting bug reports
and feature requests or writing code which can be incorporated into the module itself.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md), please read it and follow it
before contributing. If you find someone that is not respecting it please report its behaviour.

## How Can I Contribute

### Reporting Bugs

Before reporting a bug please search if there isn’t already a similar issue already open. If you find a similar issue
that is already closed, open a new one and include a link to it inside the body of the new one.

### Propose a New Feature

Before starting to implement a new feature, open the relative issue for starting an open discussion on where is can be
relevant and expose alternative solutions or potential pitfall that you can encounter. Fill all the information required
by the template.

### Local development

#### Testing

To test the application run:

```go
go test -v
```

Please note that tests require a running mongo instance on port 27017, using the following command to start on should be enough:

```sh
docker run -d --rm --name mongo -p 27017:27017 mongo
```


#### Benchmark

Performances are a critical factor for this application, before submitting a new PR make 
sure you run benchmarks and verify that results are not affected by tour changes

To run benchmark use:

```sh
go test ./... -bench=. -run=Bench  -benchmem
```

### Bench results

03/02/2022

```
goos: darwin
goarch: amd64
pkg: rond
cpu: Intel(R) Core(TM) i5-1038NG7 CPU @ 2.00GHz
BenchmarkEvaluateRequest-8            82          12741684 ns/op         3417740 B/op      85394 allocs/op
```

```
cpu: Intel(R) Core(TM) i7-10610U CPU @ 1.80GHz
BenchmarkBuildOptimizedResourcePermissionsMap-8            19207             63155 ns/op        26222 B/op         575 allocs/op
```

## Fork

If you want to fork our project, you could make it and keep in sync with our template.
All contribution which could improve the existent code base are welcome!

To keep a fork up to date, you can follow this [GitHub guide](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/syncing-a-fork).
For all the information about forks, [see this link](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/working-with-forks).
