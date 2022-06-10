# Docker Images for Osquery Testing

This configuration generates a matrix of osquery versions across different (Linux) operating systems. These images can be used for testing query results and osquery management servers.

## Download Images

Generated images can be accessed at [https://hub.docker.com/r/osquery/osquery](https://hub.docker.com/r/osquery/osquery).

To run an image:

```shell
docker run --rm osquery/osquery:5.2.3-centos7 osqueryi 'select * from os_version'
```

## Build

To build the container images:

```shell
./build.sh
```

### Push

To push the generated containers:

```shell
docker push --all-tags osquery/osquery
```

Currently @directionless and @zwass have admin access and can add a single additional user (who already has push access to the osquery repo) upon request. Note that we are limited to 3 total users with the Docker free plan.

### Versions

To set the version/OS matrix, edit the `versions`, `deb_platforms`, and `rpm_platforms` variables in the `build.sh` script.
