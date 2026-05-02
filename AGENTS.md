# AGENTS.md

## Build & Run

```bash
# Build for Windows
dotnet publish -c release -r win-x64 --sc ora2mqtt/ora2mqtt.csproj

# Build for Linux
dotnet publish -c release -r linux-x64 --sc ora2mqtt/ora2mqtt.csproj
```

## Project Structure

- `ora2mqtt/` - CLI application (depends on libgwmapi)
- `libgwmapi/` - GWM API client library
- `libgwmapi.test/` - Unit tests (xUnit, .NET 8.0)

## Running

```bash
ora2mqtt configure   # First-time setup (creates config)
ora2mqtt run         # Run with MQTT publishing
```

## Testing

```bash
dotnet test          # Run all tests (libgwmapi.test/)
```

## Linux Runtime Requirement

Linux binaries require:
1. Copy `libgwmapi/Resources/gwm_root.pem` to `/etc/ssl/certs/`
2. Use `openssl.cnf` from repo: `OPENSSL_CONF=/path/to/openssl.cnf`

## Docker

Create config on host first:
```bash
ora2mqtt configure   # Run on host to generate ora2mqtt.yml
docker run -v ./ora2mqtt.yml:/config/ora2mqtt.yml zivillian/ora2mqtt:latest
```