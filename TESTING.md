# Testing wgtunnel

This project uses `pytest` and Docker Compose for full integration testing. The test suite builds the application, spins up a virtualized WireGuard network via Docker, and verifies both Local (`-L`) and Remote (`-R`) port forwarding for TCP and UDP.

## Requirements

Ensure you have the following installed on your host system:
*   **Docker** & **Docker Compose**
*   **Make** (to build `wgtunnel`)
*   **Python 3.x**
*   **pytest** (`pip install pytest`)
*   **iperf3** (for benchmarking)

## Running the Integration Tests

1.  Navigate to the `test/` directory.
2.  Execute `pytest` directly.

```bash
cd test
pytest -v
```

### What the tests do

1.  **Setup Phase**:
    *   Builds `wgtunnel` binary in the project root.
    *   Starts a Docker container running `wireguard-go` via `docker-compose up`.
    *   Generates runtime server and client keys.
    *   Dynamically generates a `.conf` file formatted to use `wgtunnel`'s internal UAPI configuration.

2.  **Test Cases**:
    *   **TCP Local Forward (`-L`)**: Binds a local host port, forwards traffic through the WG tunnel, and validates an echo from `socat` running inside Docker.
    *   **UDP Local Forward (`-L`)**: Same as above, ensuring datagram traffic properly bridges.
    *   **TCP Remote Forward (`-R`)**: Binds a port directly on the WireGuard interface (`10.1.1.2`). Uses `docker exec` to trigger a connection from inside the container, forwarding traffic back to the physical host running a Python echo server.
    *   **UDP Remote Forward (`-R`)**: Validates UDP routing from the internal container through the reverse tunnel.

3.  **Teardown Phase**:
    *   Automatically cleans up temporary config files and tears down the Docker compose environment (`docker compose down -v`).

## Benchmarking

A Python script `benchmark.py` is included to test the throughput capabilities of `wgtunnel`. It uses `iperf3` to measure both TCP and UDP speeds for both Local (`-L`) and Remote (`-R`) port forwarding directions.

To run the benchmark:

```bash
cd test
python benchmark.py
```

The script performs the following tasks:
1.  Spins up the same Docker Compose environment as the integration tests.
2.  Runs `iperf3` in server mode (either on the host or inside the container depending on the test direction).
3.  Measures TCP upload and download throughput.
4.  Uses the TCP baseline to set a stable target for UDP throughput tests, and calculates the effective UDP bandwidth factoring in packet loss.
5.  Prints a formatted table summarizing the results in Mbps.
