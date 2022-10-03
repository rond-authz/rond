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
	go test ./... -coverprofile coverage.out
	$(MAKE) clean

.PHONY: clean
clean:
	docker rm mongo --force

.PHONY: version
version:
	sed -i.bck "s|## Unreleased|## Unreleased\n\n## ${VERSION} - ${NOW_DATE}|g" "CHANGELOG.md"
	sed -i.bck "s|SERVICE_VERSION=\"[0-9]*.[0-9]*.[0-9]*.*\"|SERVICE_VERSION=\"${VERSION}\"|" "Dockerfile"
	rm -fr "CHANGELOG.md.bck" "Dockerfile.bck"
	git add "CHANGELOG.md" "Dockerfile"
	git commit -m "Upgrade version to v${VERSION}"
	git tag v${VERSION}
