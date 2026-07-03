#!/usr/bin/env python3
"""Load test for epoll-server: N concurrent TCP connections over tap0.

Requires the server already running and tap0 already configured (see
README.md) - this only drives client connections against it. Each
connection sends a unique payload and asserts the echo matches exactly,
so a wrong echo, a dropped connection, or data crossing between
connections all show up as a failure, not just a hang or crash.

Usage (inside the same privileged Docker container the server runs in):
    python3 load_test.py [connection_count] [payload_size]
"""

import socket
import sys
import threading
import time

SERVER_IP = "10.0.0.2"
SERVER_PORT = 8080
CONNECT_TIMEOUT_SECONDS = 5
RECV_TIMEOUT_SECONDS = 5


def run_one_connection(connection_index, payload_size, results, results_lock):
    payload = ("conn-%03d-" % connection_index).encode() * (payload_size // 10 + 1)
    payload = payload[:payload_size]

    start_time = time.monotonic()
    try:
        with socket.create_connection((SERVER_IP, SERVER_PORT), timeout=CONNECT_TIMEOUT_SECONDS) as sock:
            sock.settimeout(RECV_TIMEOUT_SECONDS)
            sock.sendall(payload)

            received = bytearray()
            while len(received) < len(payload):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                received.extend(chunk)

            elapsed = time.monotonic() - start_time
            success = bytes(received) == payload
            error = None if success else "echo mismatch (got %d of %d bytes)" % (len(received), len(payload))
    except Exception as e:
        elapsed = time.monotonic() - start_time
        success = False
        error = str(e)

    with results_lock:
        results.append((connection_index, success, elapsed, error))


def main():
    connection_count = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    payload_size = int(sys.argv[2]) if len(sys.argv) > 2 else 256

    print("Load test: %d concurrent connections, %d-byte payloads, against %s:%d"
          % (connection_count, payload_size, SERVER_IP, SERVER_PORT))

    results = []
    results_lock = threading.Lock()
    threads = []

    overall_start = time.monotonic()
    for i in range(connection_count):
        thread = threading.Thread(target=run_one_connection, args=(i, payload_size, results, results_lock))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
    overall_elapsed = time.monotonic() - overall_start

    passed = [r for r in results if r[1]]
    failed = [r for r in results if not r[1]]

    print("\n--- results ---")
    for index, success, elapsed, error in sorted(failed):
        print("  connection %3d: FAIL (%.3fs) - %s" % (index, elapsed, error))

    latencies = [r[2] for r in passed]
    if latencies:
        latencies.sort()
        print("\nlatency (passed connections): min=%.3fs  median=%.3fs  max=%.3fs"
              % (latencies[0], latencies[len(latencies) // 2], latencies[-1]))

    print("\n%d/%d connections passed in %.2fs wall time" % (len(passed), connection_count, overall_elapsed))

    if failed:
        print("LOAD_TEST: FAIL")
        sys.exit(1)
    else:
        print("LOAD_TEST: PASS")
        sys.exit(0)


if __name__ == "__main__":
    main()
