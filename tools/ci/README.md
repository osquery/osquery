# Generate Docker image for the CI on Linux:

osquery-ubuntu18.04-toolchain.dockerfile is the Dockerfile used for this; it's made for a multi-architecture image (x86 and arm64).
To create a multi-architecture image we have to use the `docker buildx` command, a different driver than the one normally used and also emulation by qemu.

Using an Ubuntu 18.04 as the host:

1. Ensure `docker` is installed with `sudo apt install docker-ce`
2. Ensure that the `docker` systemd service is running with `sudo systemctl status docker`. If not start it with `sudo systemctl start docker`
3. Check with `cat /proc/sys/fs/binfmt_misc/qemu-*` that you have `interpreter /usr/bin/qemu-aarch64`. If nothing is returned, you might have to install/register arm64 emulation via `sudo docker run --privileged --rm tonistiigi/binfmt --install arm64`
4. Add a new builder instance with
  ```
  sudo docker buildx create --driver docker-container --name multiarch
  sudo docker buildx inspect --bootstrap multiarch
  ```
5. Verify that there's no error and that `Platforms` contains both `linux/amd64` and `linux/arm64`
6. Select the builder to use with `sudo docker buildx use multiarch`


Now you're ready to build, test and push the image. Use the Makefile in this folder to do so.

## Certificate bundle updates

The [update-certs workflow](../../.github/workflows/update_certs.yml) runs every
Monday at 08:23 UTC and can also be started with `workflow_dispatch`. It downloads
[curl's Mozilla CA bundle](https://curl.se/docs/caextract.html), checks its published
SHA-256 checksum and verifies that OpenSSL can parse the certificates before
updating [certs.pem](../deployment/certs.pem).

When the bundle changes, the workflow opens or updates a single pull request from
`automation/update-certs` to the repository's default branch. No pull request is
created when the bundle is unchanged. The workflow uses Git and the GitHub CLI
preinstalled on the GitHub-hosted runner to push the update branch and create or
edit the pull request; no third-party action is used. Updates require normal
maintainer review; the workflow does not merge them automatically.

In the repository's **Settings > Actions > General > Workflow permissions**,
enable **Allow GitHub Actions to create and approve pull requests**. The workflow
grants `GITHUB_TOKEN` write access to contents and pull requests; no additional
secret is required. Pull requests created with `GITHUB_TOKEN` do not trigger
`push` or `pull_request` workflows automatically, so maintainers must arrange any
required CI validation before merging.
