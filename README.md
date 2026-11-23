# jwtx — JWT Security Analyzer

A CLI utility for inspecting JWT structure, claims, timestamps, token lifetime, and signature verification.

## Install Go

On Kali Linux, install Go and confirm the version:

```bash
sudo apt update
sudo apt install -y golang
go version
```

`jwtx` requires Go 1.23 or newer. If the repository version is older, install a newer Go release from https://go.dev/dl/.

## Install jwtx with `go install`

From the directory containing `go.mod` and `main.go`, run:

```bash
go install .
```

This compiles and installs `jwtx` into Go's binary directory (normally `$(go env GOPATH)/bin`). Ensure that directory is in your `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
jwtx --version
```

To make the PATH change persistent in Bash, add the `export PATH=...` line to `~/.bashrc`, then run `source ~/.bashrc`.

> A Katana-style command such as `go install github.com/OWNER/jwtx@latest` can be provided once `jwtx` is published in a Go-accessible repository. Replace `OWNER` with the actual repository owner; do not use this placeholder as a real install command.

## Build

Requires Go 1.23+ and network access on the build machine for the Go module dependency.

```bash
go mod tidy
go build -trimpath -ldflags="-s -w" -o jwtx .
```

## Usage

```bash
./jwtx -t "YOUR.JWT.TOKEN"
./jwtx -f token.txt
./jwtx -f token.txt -o report.json
./jwtx -f token.txt -o report.txt
./jwtx -f token.txt --secret "HMAC_SECRET"
./jwtx -f token.txt --public-key public.pem
./jwtx --version
./jwtx -f token.txt --no-color
```

## Missing expiration claim

When `exp` is absent, jwtx reports `NO EXPIRATION CLAIM`, leaves remaining lifetime undefined, and reports total lifetime as undetermined. This means the token itself does not declare an expiration; it does not prove that the server will accept it indefinitely. Server-side expiry and revocation must be tested separately.

## Signature verification

A decoded JWT is not automatically authentic. Supply the matching HMAC secret or public key to verify its signature. Time-based status is a local claim analysis, not proof of server acceptance or revocation state.

## Colored output

jwtx uses ANSI colors automatically in interactive terminals: green for successful checks, red for expired/invalid states and failures, yellow for warnings and missing claims, blue for section headings, and cyan/gray for informational output. Colors are disabled automatically when output is redirected or piped. Use `--no-color` or set the standard `NO_COLOR` environment variable to disable them. JSON and TXT exports do not contain ANSI color codes.
