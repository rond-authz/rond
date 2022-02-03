# rbac-service

This is a simple Go application template with a pre-configured [logger]("https://github.com/mia-platform/glogger") and a [library]("https://github.com/mia-platform/configlib") to handle configuration file and env variables.
It also contains basic dependencies for testing and http request.
By default the module name is "service", if you want to change it, please remember to change it in the imports too.

## Development Local

To develop the service locally you need:
    - Go 1.13+

To start the application locally

```go
go run rbac-service
```

By default the service will run on port 8080, to change the port please set `HTTP_PORT` env variable

## Testing

To test the application use:

Please remember to have a mongo instance running on your localhost on port 27017 using the following command:

```sh
docker run --rm -p 27017:27017 mongo
```

```go
go test -v
```

## Benchmark

To run benchmark use:

```sh
go test ./... -bench=. -run=Bench  -benchmem
```

### Bench results

03/02/2022 - h18

```
goos: darwin
goarch: amd64
pkg: git.tools.mia-platform.eu/platform/core/rbac-service
cpu: Intel(R) Core(TM) i5-1038NG7 CPU @ 2.00GHz
BenchmarkEvaluateRequest-8            82          12741684 ns/op         3417740 B/op      85394 allocs/op
```
