# jwtx — JWT Security Analyzer

`jwtx` is a command-line JWT security analyzer. It decodes JWT headers and payloads, evaluates standard claims and timestamps, analyzes token lifetime, and optionally verifies JWT signatures.

## Features

- Decode JWT header and payload.
- Display `alg`, `typ`, and `kid`.
- Analyze `iat`, `nbf`, and `exp` timestamps in IST.
- Calculate token age, lifetime, and remaining lifetime when the required claims are available.
- Identify missing or invalid claims and other security observations.
- Verify HMAC signatures using a supplied secret.
- Verify asymmetric signatures using a supplied public key.
- Export reports in JSON or TXT format.
- Display color-coded terminal output, with an option to disable colors.

## Installation

### Method 1: Install with Go

Requires Go 1.23 or newer.

Install Go on Kali Linux:

```bash
sudo apt update
sudo apt install -y golang
go version
```

If the version provided by your package repository is older than 1.23, install a newer release from the official Go downloads page:

https://go.dev/dl/

Install `jwtx`:

```bash
go install github.com/0xdeba/jwtx@latest
```

The executable is normally installed in `$(go env GOPATH)/bin`. Add that directory to your `PATH` if it is not already there:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

To persist this change for Bash:

```bash
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
source ~/.bashrc
```

Verify the installation:

```bash
jwtx --version
jwtx -h
```

**Repository requirement:** The repository's `go.mod` must declare this exact module path:

```go
module github.com/0xdeba/jwtx
```

The module path must be committed to GitHub. Publish a proper Go module version tag (for example, `v1.0.0`) for versioned installation. The `@latest` suffix installs the latest version Go can resolve from the repository.

### Method 2: Download the precompiled binary

For the published Linux binary:

```bash
sudo curl -L \
  "https://github.com/0xdeba/jwtx/releases/download/v1/jwtx" \
  -o /usr/local/bin/jwtx

sudo chmod +x /usr/local/bin/jwtx
```

Verify:

```bash
jwtx --version
jwtx -h
```

This method does not require Go. The binary must match your operating system and CPU architecture.

### Method 3: Build from source

Clone the repository and build locally:

```bash
git clone https://github.com/0xdeba/jwtx.git
cd jwtx

go mod tidy
go build -trimpath -ldflags="-s -w" -o jwtx .
```

Run:

```bash
./jwtx --version
```

Optionally install the locally built binary system-wide:

```bash
sudo install -m 755 jwtx /usr/local/bin/jwtx
```

## Usage

Analyze a JWT supplied directly:

```bash
jwtx -t "YOUR.JWT.TOKEN"
```

Analyze a JWT from a file:

```bash
jwtx -f token.txt
```

Export a JSON report:

```bash
jwtx -f token.txt -o report.json
```

Export a TXT report:

```bash
jwtx -f token.txt -o report.txt
```

Verify an HMAC-signed JWT:

```bash
jwtx -f token.txt --secret "YOUR_HMAC_SECRET"
```

Verify an RSA, ECDSA, or EdDSA JWT using a public-key PEM file:

```bash
jwtx -f token.txt --public-key public.pem
```

Show the version:

```bash
jwtx --version
```

Show help:

```bash
jwtx -h
```

Disable colored terminal output:

```bash
jwtx -f token.txt --no-color
```

## Command-line options

| Option | Description |
|---|---|
| `-t` | JWT token supplied directly |
| `-f` | Path to a file containing the JWT |
| `-o` | Export report as `.json` or `.txt` |
| `--secret` | HMAC signing secret for signature verification |
| `--public-key` | Public-key PEM file for asymmetric signature verification |
| `--version` | Display the tool version |
| `--no-color` | Disable colored terminal output |

Provide exactly one of `-t` or `-f`. Use either `--secret` or `--public-key` for signature verification, not both.

## Colored output

When writing to an interactive terminal, `jwtx` uses ANSI colors:

- **Green:** successful checks and verified signatures.
- **Red:** expired or invalid states and failed checks.
- **Yellow:** warnings, missing claims, and undetermined results.
- **Blue:** section headings.
- **Cyan/gray:** informational output.

Colors are automatically disabled when output is redirected or piped. You can also disable them with `--no-color` or by setting the standard `NO_COLOR` environment variable. JSON and TXT report files do not contain ANSI color codes.

## Understanding token status and claims

- `iat` (*Issued At*) indicates when the token was issued.
- `nbf` (*Not Before*) indicates the earliest time the token should be accepted.
- `exp` (*Expiration Time*) indicates when the token expires.

If `nbf` is in the future, `jwtx` reports the token as not yet valid. If `exp` is in the past, it reports the token as expired.

If `exp` is absent, `jwtx` reports `NO EXPIRATION CLAIM`. Remaining lifetime is left undefined and total lifetime is reported as undetermined. This means the JWT does not declare an expiration through the `exp` claim; it does **not** prove that the server will accept the token indefinitely. The application may enforce expiration or revocation separately.

## Signature verification and limitations

Decoding a JWT does not verify its signature or establish that the token is authentic.

- For HMAC algorithms (such as `HS256`), provide the matching shared secret with `--secret`.
- For asymmetric algorithms (such as `RS256` or `ES256`), provide the corresponding public key with `--public-key`.

Without a matching key, `jwtx` can still decode the token and analyze its claims and timestamps, but it cannot confirm the signature.

A time-based status is a local analysis of the token's claims. It does not prove that a server will accept or reject the token, nor does it establish server-side revocation state. Validate those behaviors separately during an authorized assessment.

## License

See the repository for license information.
