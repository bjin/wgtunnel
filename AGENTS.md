# Agent Guidelines for wgtunnel

Welcome, Agent. This document provides essential information for working within the `wgtunnel` repository. Please read and adhere to these guidelines to ensure consistency, quality, and smooth collaboration.

## 1. Project Overview

`wgtunnel` is a lightweight Go application that provides a WireGuard-based tunneling solution. It allows forwarding local ports to a WireGuard network (`-L` flags) and remote WireGuard ports back to the local host (`-R` flags). It runs entirely in user-space using `netstack` and `golang.zx2c4.com/wireguard`.

## 2. Build, Lint, and Test Commands

### 2.1. Building the Project
The project uses a simple `Makefile` to build a statically linked binary.

*   **Standard Build:**
    ```bash
    make
    ```
    This executes: `CGO_ENABLED=0 go build -ldflags="-s -w"`.
*   **Manual Build (if Makefile is unavailable):**
    ```bash
    go build -o wgtunnel main.go
    ```

### 2.2. Testing
The project uses `pytest` and Docker Compose for full integration testing. The test suite spins up a virtualized WireGuard network and verifies both Local (`-L`) and Remote (`-R`) port forwarding for TCP and UDP.

*   **Run integration tests:**
    ```bash
    cd test && pytest -v
    ```
*   **Run a specific test:**
    ```bash
    cd test && pytest -v -k "test_local_forward_tcp"
    ```
*   **See [TESTING.md](TESTING.md) for more detailed testing infrastructure overview.**

### 2.3. Linting and Formatting
Consistent code style is enforced via standard Go tools. Ensure your code passes these checks before finalizing changes.

*   **Format code:**
    ```bash
    go fmt ./...
    ```
    *Agents must run this command after any code modification.*
*   **Vet code (static analysis):**
    ```bash
    go vet ./...
    ```
*   **Advanced Linting (if `golangci-lint` is installed):**
    ```bash
    golangci-lint run
    ```

## 3. Code Style and Conventions

This project follows idiomatic Go standards. 

### 3.1. General Formatting
*   **Indentation:** Use tabs for indentation, not spaces (standard `gofmt` behavior). Do not convert tabs to spaces.
*   **Line Length:** While Go doesn't have a strict line length limit, try to keep lines readable. Break long function signatures or chained calls where logical.

### 3.2. Naming Conventions
*   **Packages:** Use short, concise, lowercase names without `_` or `-` (e.g., `netstack`, `device`).
*   **Files:** Use `snake_case` for file names (e.g., `main.go`, `config_parser.go`).
*   **Variables/Functions:** Use `camelCase` for unexported identifiers and `PascalCase` for exported ones.
*   **Acronyms:** Keep acronyms in the same case (e.g., `TCPAddr`, `localIP`, not `TcpAddr` or `localIp`).
*   **Interfaces:** Interface names should generally end in `-er` (e.g., `Reader`, `Writer`, `Formatter`).

### 3.3. Imports
*   Group imports into standard library packages and third-party packages, separated by an empty line. This is handled automatically by tools like `goimports`.
    ```go
    import (
    	"context"
    	"fmt"
    	"net"

    	"golang.zx2c4.com/wireguard/device"
    )
    ```

### 3.4. Error Handling
*   **Idiomatic Checks:** Always check errors explicitly. Avoid ignoring errors with `_` unless explicitly documented why it's safe.
    ```go
    if err := doSomething(); err != nil {
        return fmt.Errorf("failed to do something: %w", err)
    }
    ```
*   **Fatal Errors:** Use `log.Fatalf` only during initialization (e.g., in `main()` or initial setup functions) when the application cannot recover.
*   **Logging:** For non-fatal errors during operation (e.g., a single connection failing), use `log.Printf` to record the issue without stopping the entire service. Include context in log messages (e.g., `[Local TCP] Accept error: %v`).

### 3.5. Types and Data Structures
*   Prefer strong typing. Define custom structs for related data (e.g., `TunnelConfig`).
*   Avoid `interface{}` unless necessary for generic programming, or when dealing with truly unknown types.
*   When defining custom flag parsing logic (like `stringSlice`), implement the `flag.Value` interface methods (`String` and `Set`).
