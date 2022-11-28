all:
	@echo Targets to build the `osquery/builder` docker image.

# There are a couple of caveats about using buildx and multiplatform
# builds. First, docker itself doesn't support them. So you cannot
# build a multiplatform image, and then push to the local docker
# instance. Thus, these targets are for building and pushing to the
# remote, and building some test images locally.
container:
	docker buildx build --platform linux/amd64,linux/arm64 -f osquery-ubuntu18.04-toolchain.dockerfile .

# push uses the cached builds from `container`
push: TAG = $(shell git rev-parse --short HEAD)
push: container
	docker buildx build --platform linux/amd64,linux/arm64 --push -t osquery/builder18.04:$(TAG) -f osquery-ubuntu18.04-toolchain.dockerfile .

# These targets use --load, which pushes to the local docker
# install. Only a single platform is supported.
arm:
	docker buildx build --platform linux/arm64 --load -t osquerybuilder:$@  -f osquery-ubuntu18.04-toolchain.dockerfile .
x86:
	docker buildx build --platform linux/amd64 --load -t osquerybuilder:$@ -f osquery-ubuntu18.04-toolchain.dockerfile .
