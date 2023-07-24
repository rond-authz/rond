VERSION ?= latest

# Create a variable that contains the current date in UTC
# Different flow if this script is running on Darwin or Linux machines.
ifeq (Darwin,$(shell uname))
	NOW_DATE = $(shell date -u +%d-%m-%Y)
else
	NOW_DATE = $(shell date -u -I)
endif

all: test

.PHONY: mongo-start
mongo-start:
	docker run --rm --name mongo -p 27017:27017 -d mongo

.PHONY: test
test: clean mongo-start
	go test ./... -cover
	$(MAKE) clean

.PHONY: coverage
coverage: clean mongo-start
	go test ./... -coverprofile coverage.out
	$(MAKE) clean

.PHONY: bench
bench: clean mongo-start
	go test -benchmem -bench=^Bench ./... -run=^Bench

.PHONY: clean
clean:
	docker rm mongo --force

.PHONY: version
version:
	sed -i.bck "s|SERVICE_VERSION=\"[0-9]*.[0-9]*.[0-9]*.*\"|SERVICE_VERSION=\"${VERSION}\"|" "Dockerfile"
	rm -fr "Dockerfile.bck"
	git add "Dockerfile"
	git commit -m "Upgrade version to v${VERSION}"
	git tag v${VERSION}
