# Intel macOS dependency build

Apple Silicon and Intel macOS connector builds are supported. The locked
cryptography release currently has no Intel macOS wheel on PyPI, so this
repository builds and verifies an Intel wheel with statically linked OpenSSL.
Users of a packaged connector do not need Rust, Xcode or Homebrew to compile
this dependency.

The `intel-wheel.yml` workflow restores a matching stored wheel only after the
quality and security gates pass. It compiles from pinned sources only when no
matching verified build exists. The native library is stored as a GitHub
release asset named `native-intel-<build-key>`. This is a connector build
dependency, not an application release. The ZIP contains the wheel, source and
build manifest, component SBOM, and toolchain inventory.

The SHA-256 build key covers the cryptography and OpenSSL sources, locked Python
build tools, CPython/macOS/architecture target, uv version and build recipe.
Changing a native input changes the key. An unrelated connector source change
does not.

Before use, CI verifies GitHub provenance from this repository's main-branch
validation workflow, archive contents and size, wheel metadata, source hashes,
build key and wheel checksum. Only an HTTP 404 means a release is absent and
allows a source build. Network or authorization errors, missing assets, bad
hashes and invalid provenance fail closed. An invalid stored release is never
silently replaced by a build.

## Initial bootstrap

`dependencies/intel-bootstrap.json` pins a successful Intel dependency build
inherited from the companion repository, including its producer job, source
revision, original build commit, build key and exact wheel SHA-256. Its producer
compiled pinned OpenSSL and passed upstream, cryptography and component scan
checks. The bootstrap is accepted only when its producer and artifact metadata
match and the wheel bytes match the recorded hash. It is not a general-purpose
artifact fallback. After this repository has published its own durable,
attested dependency release, remove the bootstrap in a reviewed change.

## Build and verification

The workflow installs only locked binary build tools, fetches cryptography's
exact locked source over HTTPS and checks its size and SHA-256 before safe
extraction. It requires the upstream Cargo lockfile and locked Maturin settings.
The extracted upstream dependencies are scanned. On a cache miss only, the
workflow downloads the pinned OpenSSL LTS source from its official release,
checks its recorded size and hash, runs its upstream test suite, and builds
static Intel libraries. It then builds cryptography without build isolation or
dependency re-resolution.

The resulting wheel is checked for exact package metadata and hashes. CI tests
AES-GCM, Fernet, Ed25519/RSA signing, PEM loading, tamper rejection and static
linkage. It records the embedded OpenSSL version in a CycloneDX SBOM; Trivy
scans the Python component and Grype checks the OpenSSL CPE. HIGH and CRITICAL
findings block use. These checks also run for a restored wheel.

The verified wheel and metadata are shared only within the workflow run.
Downstream Intel tests and connector packaging verify the same artifact and
install it with hashes, without source builds. Pull request jobs cannot publish
durable dependency releases. Main-branch publication runs only after the
required test, image, quality and security gates pass and never overwrites an
existing release asset.

## Limits and maintenance

This is not a claim of bit-for-bit reproducibility across runner images. The
SBOM covers cryptography and its embedded OpenSSL, not the complete connector.
Runtime and build dependency audits, repository scans and container image scans
remain separate. A statically linked OpenSSL fix requires a rebuild and new
build key. OpenSSL source changes require a reviewed update to
`dependencies/openssl.json`.

The recipe follows upstream [cryptography macOS build documentation](https://cryptography.io/en/latest/installation/#building-cryptography-on-macos).
The pinned OpenSSL LTS lifecycle is documented on the
[official source download page](https://openssl-library.org/source/).
