#!/usr/bin/env bash
# ==============================================================================
# AWS Nitro Enclave Hardware Attestation Probe
#
# @spec SCC-NITRO-001 SCC-NITRO-003 SCC-NITRO-006
#
# PURPOSE:
# Automated end-to-end hardware probe to generate and extract an authentic,
# cryptographically signed AWS Nitro Enclave attestation document (COSE Sign1)
# directly from the AWS Nitro Security Module (/dev/nsm).
#
# ARCHITECTURAL DESIGN:
# 1. Zero-dependency static probe:
#    Builds a minimal C probe (`nsm_probe.c`) inside an isolated Alpine musl
#    Docker container. Eliminates host compiler requirements and produces a
#    reproducible, 100% static binary.
# 2. Production-mode execution:
#    Launches the enclave in production mode (non-debug). This guarantees that
#    the Nitro hypervisor populates valid, non-zero hardware PCR measurements
#    (PCR0, PCR1, PCR2).
# 3. Secure vsock communication:
#    Because serial console sockets are disabled in production mode, the probe
#    establishes an AF_VSOCK socket directly to the parent EC2 instance (CID 3,
#    port 5005) to transmit the raw attestation payload.
# 4. Host receiver and artifact extraction:
#    The parent instance runs a lightweight vsock listener in Python, receives
#    the COSE Sign1 document, terminates the enclave, and saves the binary
#    artifact to `/tmp/nitro_attestation_hardware.bin`.
#
# PREREQUISITES:
# - AWS EC2 instance with Nitro Enclaves enabled (e.g. c6i.xlarge, >=4 vCPUs)
# - Packages: aws-nitro-enclaves-cli, docker, python3
# - Allocator configured: >= 1024 MiB memory, 2 CPUs in /etc/nitro_enclaves/allocator.yaml
#
# OUTPUT ARTIFACTS:
# - /tmp/nitro_attestation_hardware.bin (Raw DER/COSE Sign1 binary)
# - /tmp/nitro_attestation_hardware.b64 (Base64-encoded attestation document)
# ==============================================================================
set -euo pipefail

echo "=== AWS NITRO ENCLAVE AUTOMATED HARDWARE PROBE ==="

# 0. Use an already provisioned host. Docker access is root-equivalent;
# an operator must grant docker/ne group membership outside this probe and
# re-login, configure the allocator, and start services before running it.
# Never change host permissions, service state, or another enclave here.
for command in docker nitro-cli python3; do
    command -v "$command" >/dev/null || { echo "Missing prerequisite: $command" >&2; exit 1; }
done
if ! docker info >/dev/null 2>&1; then
    echo "Docker is unavailable to this user; ask the host operator to provision access." >&2
    exit 1
fi
if [[ ! -r /dev/nitro_enclaves || ! -w /dev/nitro_enclaves ]]; then
    echo "Nitro device access is unavailable; ask the host operator to provision ne group access." >&2
    exit 1
fi
for directory in /run/nitro_enclaves /var/log/nitro_enclaves; do
    if [[ ! -d "$directory" || ! -w "$directory" || ! -x "$directory" ]]; then
        echo "Nitro runtime directory is unavailable: $directory; ask the host operator to provision it." >&2
        exit 1
    fi
done

WORK_DIR="$(mktemp -d /tmp/nitro-probe-XXXXXX)"
cd "$WORK_DIR"
echo "[*] Working directory: $WORK_DIR"

# 1. Write standalone NSM probe in C with vsock transport
cat << 'EOF' > nsm_probe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <sys/socket.h>

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

struct sockaddr_vm {
    unsigned short svm_family;
    unsigned short svm_reserved1;
    unsigned int svm_port;
    unsigned int svm_cid;
    unsigned char svm_zero[sizeof(struct sockaddr) - sizeof(unsigned short)*2 - sizeof(unsigned int)*2];
};

#define NSM_REQUEST_ATTESTATION 0xC0200A00

struct nsm_iovec {
    uint64_t iov_base;
    uint64_t iov_len;
};

struct nsm_message {
    struct nsm_iovec request;
    struct nsm_iovec response;
};

static void push_cbor_arg(uint8_t *out, size_t *pos, uint8_t major, uint64_t val) {
    uint8_t hi = major << 5;
    if (val <= 23) {
        out[(*pos)++] = hi | (uint8_t)val;
    } else if (val <= 0xFF) {
        out[(*pos)++] = hi | 24;
        out[(*pos)++] = (uint8_t)val;
    } else if (val <= 0xFFFF) {
        out[(*pos)++] = hi | 25;
        out[(*pos)++] = (val >> 8) & 0xFF;
        out[(*pos)++] = val & 0xFF;
    } else if (val <= 0xFFFFFFFF) {
        out[(*pos)++] = hi | 26;
        out[(*pos)++] = (val >> 24) & 0xFF;
        out[(*pos)++] = (val >> 16) & 0xFF;
        out[(*pos)++] = (val >> 8) & 0xFF;
        out[(*pos)++] = val & 0xFF;
    }
}

static void push_cbor_bstr(uint8_t *out, size_t *pos, const uint8_t *b, size_t len) {
    push_cbor_arg(out, pos, 2, len);
    memcpy(&out[*pos], b, len);
    *pos += len;
}

static void push_cbor_tstr(uint8_t *out, size_t *pos, const char *s) {
    size_t len = strlen(s);
    push_cbor_arg(out, pos, 3, len);
    memcpy(&out[*pos], s, len);
    *pos += len;
}

int main() {
    int fd = open("/dev/nsm", O_RDWR);
    if (fd < 0) {
        return 1;
    }

    uint8_t user_data[32];
    memset(user_data, 0x55, 32);
    uint8_t nonce[32];
    memset(nonce, 0x77, 32);

    uint8_t req_buf[4096];
    size_t req_len = 0;
    push_cbor_arg(req_buf, &req_len, 5, 1);
    push_cbor_tstr(req_buf, &req_len, "Attestation");
    push_cbor_arg(req_buf, &req_len, 5, 2);
    push_cbor_tstr(req_buf, &req_len, "user_data");
    push_cbor_bstr(req_buf, &req_len, user_data, 32);
    push_cbor_tstr(req_buf, &req_len, "nonce");
    push_cbor_bstr(req_buf, &req_len, nonce, 32);

    uint8_t resp_buf[16384];
    struct nsm_message msg;
    msg.request.iov_base = (uint64_t)req_buf;
    msg.request.iov_len = req_len;
    msg.response.iov_base = (uint64_t)resp_buf;
    msg.response.iov_len = sizeof(resp_buf);

    int rc = ioctl(fd, NSM_REQUEST_ATTESTATION, &msg);
    if (rc != 0) {
        close(fd);
        return 2;
    }
    close(fd);

    // Connect to host on CID 3, port 5005
    int s = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (s < 0) {
        return 3;
    }

    struct sockaddr_vm sa;
    memset(&sa, 0, sizeof(sa));
    sa.svm_family = AF_VSOCK;
    sa.svm_cid = 3; // Parent host CID is 3
    sa.svm_port = 5005;

    int connected = 0;
    for (int i = 0; i < 50; i++) {
        if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
            connected = 1;
            break;
        }
        usleep(200000);
    }

    if (!connected) {
        close(s);
        return 4;
    }

    size_t total_sent = 0;
    while (total_sent < msg.response.iov_len) {
        ssize_t n = send(s, resp_buf + total_sent, msg.response.iov_len - total_sent, 0);
        if (n <= 0) break;
        total_sent += n;
    }

    close(s);
    return 0;
}
EOF

# 2. Multi-stage Docker build: compiles statically via Alpine musl
cat << 'EOF' > Dockerfile.nitro_probe
FROM alpine:3.19 AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY nsm_probe.c .
RUN gcc -static -O2 nsm_probe.c -o /nsm_probe

FROM scratch
COPY --from=builder /nsm_probe /nsm_probe
ENTRYPOINT ["/nsm_probe"]
EOF

echo "[*] Building minimal enclave Docker container..."
docker build --no-cache -t nitro-probe:latest -f Dockerfile.nitro_probe .

# 3. Build Enclave Image File (EIF)
echo "[*] Packaging Enclave Image File (EIF)..."
nitro-cli build-enclave --docker-uri nitro-probe:latest --output-file nitro-probe.eif

# 4. Start Host vsock receiver in Python
cat << 'EOF' > recv_vsock.py
import socket
import sys

s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s.bind((socket.VMADDR_CID_ANY, 5005))
s.listen(1)
s.settimeout(30.0)
print("[*] Host vsock receiver listening on port 5005...", flush=True)

try:
    conn, addr = s.accept()
    print(f"[*] Accepted vsock connection from enclave CID {addr[0]}", flush=True)
    data = bytearray()
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    conn.close()
    s.close()
    if len(data) > 0:
        with open("/tmp/nitro_attestation_hardware.bin", "wb") as f:
            f.write(data)
        print(f"[*] Attestation document saved: {len(data)} bytes", flush=True)
    else:
        print("[-] Zero bytes received from enclave", flush=True)
        sys.exit(1)
except Exception as e:
    print(f"[-] vsock receiver error: {e}", flush=True)
    sys.exit(2)
EOF

python3 recv_vsock.py &
RECV_PID=$!
sleep 1

# 5. Launch Enclave (production mode, no console needed)
echo "[+] Launching AWS Nitro Enclave..."
ENCLAVE_OUTPUT=$(nitro-cli run-enclave --cpu-count 2 --memory 1024 --eif-path nitro-probe.eif)
echo "$ENCLAVE_OUTPUT"
EID=$(echo "$ENCLAVE_OUTPUT" | grep -o '"EnclaveID": "[^"]*' | cut -d'"' -f4 || true)

# Wait for receiver
wait $RECV_PID

# Terminate enclave once payload is captured
if [ -n "$EID" ]; then
    echo "[*] Terminating enclave $EID..."
    nitro-cli terminate-enclave --enclave-id "$EID" >/dev/null 2>&1 || true
fi

# 6. Verify and output base64
if [ -f /tmp/nitro_attestation_hardware.bin ] && [ -s /tmp/nitro_attestation_hardware.bin ]; then
    BIN_LEN=$(wc -c < /tmp/nitro_attestation_hardware.bin | tr -d ' ')
    base64 -w 0 /tmp/nitro_attestation_hardware.bin > /tmp/nitro_attestation_hardware.b64 2>/dev/null || base64 /tmp/nitro_attestation_hardware.bin | tr -d '\n' > /tmp/nitro_attestation_hardware.b64
    echo ""
    echo "================================================================"
    echo "[SUCCESS] Captured hardware Nitro attestation document ($BIN_LEN bytes)!"
    echo "Saved to: /tmp/nitro_attestation_hardware.bin"
    echo ""
    echo "--- BEGIN BASE64 ATTESTATION ---"
    cat /tmp/nitro_attestation_hardware.b64
    echo ""
    echo "--- END BASE64 ATTESTATION ---"
    echo "================================================================"
else
    echo "[-] Failed to capture attestation document."
    exit 1
fi
