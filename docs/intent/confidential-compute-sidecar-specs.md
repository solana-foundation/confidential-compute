# Solana Confidential Compute Enclave Sidecar Specifications

## Specification Catalog

### @spec SCC-SIDECAR-001: Ephemeral Key Lifecycle & Zeroization
WHEN the sidecar starts inside a confidential enclave,  
THE sidecar SHALL generate an ephemeral Ed25519 keypair in enclave memory from the OS CSPRNG;  
AND THE secret key material SHALL be protected with `Zeroize` and `ZeroizeOnDrop`;  
AND THE secret SHALL NOT be written to disk, persistent storage, logs, or any non-loopback interface;  
AND authorized `POST /v1/renew` SHALL attest a candidate key before replacing the active key and deadlines together, then drop the previous secret so it is zeroized; failed or cancelled enrollment SHALL retain the previous key and deadlines;<br>
OTHERWISE the sidecar SHALL refuse to sign or register a workload key whose secret has left enclave memory.

### @spec SCC-SIDECAR-002: AMD SEV-SNP Guest Ioctl Attestation Requester
WHEN the enclave mode is AMD SEV-SNP,  
THE sidecar SHALL request a report from the Linux guest driver at `/dev/sev-guest` with `SNP_GET_REPORT`;  
AND THE request SHALL place the ephemeral Ed25519 public key in `user_data[0..32]` and the Solana slot hash in `user_data[32..64]`;  
AND THE sidecar SHALL accept the report only when it is exactly 1,184 bytes, the report version is non-zero, and `REPORT_DATA` echoes that `user_data`;  
OTHERWISE the request SHALL fail closed with an ioctl error and SHALL NOT submit a registration.

### @spec SCC-SIDECAR-003: GCP Confidential Space Token Requester
WHEN the enclave mode is Google Cloud Confidential Space,\
THE sidecar SHALL fetch an OIDC attestation token from the Confidential Space launcher with `POST http://localhost/v1/token` over `/run/container_launcher/teeserver.sock`;\
AND THE JSON request SHALL contain `token_type: "OIDC"`, the configured `audience` (default `solana-confidential-compute-verifier`), and a two-element `nonces` array;\
AND nonce 0 SHALL be the unpadded base64url encoding of the 32-byte workload pubkey and nonce 1 SHALL be the unpadded base64url encoding of the 32-byte slot hash (@spec SCC-JWT-005);\
AND THE sidecar SHALL reject a token whose audience differs from the requested audience or whose decoded `eat_nonce` pair does not equal those raw bytes;\
AND missing socket, transport failure, non-success HTTP status, or invalid Confidential Space claims SHALL fail closed;\
AND THE sidecar SHALL NOT encode the nonce as UTF-8 of the raw key or as hexadecimal;\
OTHERWISE the request SHALL fail closed and SHALL NOT build a Mode A registration.

The transport follows the [Google Cloud launcher API](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources). Controlled socket tests are component simulations; genuine Google-issued tokens and hardware execution require separate evidence.

### @spec SCC-SIDECAR-004: Local Loopback RPC API & Access Control
WHEN the sidecar serves the workload,  
THE HTTP listener SHALL bind only to `127.0.0.1` or `::1` and SHALL refuse every other address;  
AND THE routes SHALL be `GET /v1/status`, `POST /v1/attest`, `POST /v1/sign`, and `POST /v1/renew`;  
AND THE on-disk payer key SHALL pay Solana fees only and SHALL NOT be the workload signer;  
AND `POST /v1/attest` and `POST /v1/renew` SHALL require an operator bearer token loaded from `--enrollment-token-file` / `SOLANA_CC_ENROLLMENT_TOKEN_FILE`, fail closed with 403 when unset and return 401 for invalid credentials before provider/RPC work;<br>
AND both routes SHALL share a monotonic cooldown of `--enrollment-min-interval-secs` / `SOLANA_CC_ENROLLMENT_MIN_INTERVAL_SECS` (default 300, range 60–86400 seconds), count failed/cancelled authorized attempts, and reject concurrent or cooling-down requests with 429 and `Retry-After`;<br>
AND HTTP and autonomous enrollment SHALL serialize key/status changes through one operation lock; heartbeat SHALL retain its configured renewal schedule without requiring an HTTP token;<br>
OTHERWISE the process SHALL exit before accepting a connection.

### @spec SCC-SIDECAR-005: Autonomous Dual-Deadline Monitoring & Attestation Renewal Daemon
WHEN the sidecar is running,  
THE live heartbeat SHALL read the canonical V2 session and trusted cluster Clock and re-attest the current ephemeral key when either remaining slots are within the configured slot buffer or remaining Unix seconds are within the configured seconds buffer, or the session is invalid;<br>
AND THE seconds buffer SHALL default to 60 and MAY be configured with `with_renewal_buffer_seconds`; host wall time SHALL NOT determine live renewal;<br>
AND THE heartbeat SHALL NOT rotate the workload key;  
AND when no enrollment deadline exists, THE heartbeat SHALL retry enrollment of the current key at the configured polling interval, including after transient enrollment failures;
AND authorized `POST /v1/renew` SHALL attest a candidate before replacing the active session and zeroizing its previous key;<br>
AND `DRY_RUN=true` SHALL build the registration transaction locally and SHALL NOT submit it or call Google metadata;  
AND tests SHALL mock both the metadata client and the Solana RPC client;  
OTHERWISE renewal SHALL fail closed; a failed refresh SHALL retain the old deadlines for retry and SHALL NOT create a new active-session claim. Dry-run heartbeat scheduling MAY use simulated slot deadlines and SHALL NOT be treated as confirmed dual-deadline evidence.

### @spec SCC-SIDECAR-008: Bounded Live Hardware Mode A Transport
WHEN live AMD SNP or AWS Nitro Mode A enrollment uses oversized hardware evidence,<br>
THE sidecar SHALL submit begin, ordered uploads of at most 700 payload bytes each, seal, consume, then close, with a fresh blockhash for each packet and a final signed serialized size of at most 1,232 bytes per transaction;<br>
AND consume SHALL request an explicit 1,400,000 compute-unit limit; this is a requested budget, not measured usage or proof that genuine verification fits;<br>
AND SNP planning SHALL use `solana_confidential_compute_sdk::staged::build_staged_snp_registration(program_id, authority, workload, nonce_slot, report, current_slot, expiry_slot)`, while Nitro SHALL reuse `build_staged_nitro_registration`;<br>
AND consume SHALL invoke the original genuine verification handler, preserving its signature/root, workload consent, identity, policy, freshness and replay guards; staging and sealing SHALL NOT authenticate hardware evidence by themselves;<br>
AND staged Mode B SHALL fail closed: this path provides no staged atomic consumer adapter;<br>
AND cleanup SHALL be attempted after a stage submission failure as well as success, with confirmed enrollment plus failed cleanup reported distinctly so callers do not treat cleanup failure as permission to reuse a consumed nonce;<br>
OTHERWISE enrollment SHALL fail without bypassing packet limits or genuine verification guards.

Source: [stage planning](../../crates/solana-confidential-compute-sdk/src/staged.rs), [packet submission](../../bins/solana-confidential-compute-sidecar/src/onchain.rs) (`submit_stage`, `submit_packet`), and [transport dispatch](../../programs/solana-confidential-compute-verifier/src/transport.rs). Select the coordinated #268 implementation. The #265 cryptographic runtime prerequisite remains: source, native/mock execution, signed packet sizing and a requested compute budget do not establish production readiness, successful genuine verification on real SBF, fresh hardware enrollment, or deployment.

### @spec SCC-SIDECAR-006: Hardened Multi-Arch Containerization
WHEN the sidecar is packaged,  
THE image SHALL be produced by a multi-stage build that copies only the release binary into a distroless non-root runtime;  
AND THE container command SHALL bind the HTTP API to `127.0.0.1:8080`;  
OTHERWISE the image SHALL NOT be used as a Confidential Space or SEV-SNP workload.


### @spec SCC-SIDECAR-007: Confirmed V2 Session Deadlines and Status
WHEN live enrollment succeeds,<br>
THE sidecar SHALL persist `registered_slot`, `expires_slot`, and `expires_unix_timestamp` from the confirmed canonical V2 attested-signer record; it SHALL NOT infer the effective Unix deadline from slots or report success solely from a locally built transaction;<br>
WHEN `GET /v1/status` refreshes a previously enrolled live session,<br>
THE sidecar SHALL read the canonical V2 record with trusted Clock `current_slot` and `current_unix_timestamp`, and SHALL report `active` only when `current_slot <= expires_slot` AND `0 <= current_unix_timestamp < expires_unix_timestamp`; slot equality is valid and Unix-deadline equality is expired;<br>
AND THE response SHALL expose `registered_slot`, `expires_slot`, `expires_unix_timestamp`, trusted `current_unix_timestamp`, `remaining_slots`, and `remaining_seconds`; remaining time SHALL saturate at zero;<br>
AND failure to read confirmed state SHALL report `unknown` for a previously enrolled live session, with no trusted current time or remaining-time values; cached deadlines MAY remain visible but SHALL NOT establish validity;<br>
AND a session without a prior enrollment deadline SHALL report `unattested`, while dry-run enrollment SHALL report `simulated`, distinctly from live `active` or `expired`;<br>
OTHERWISE the sidecar SHALL NOT present local estimates, simulation results, or stale cached state as a confirmed active session.

Source contract: [canonical session reads](../../bins/solana-confidential-compute-sidecar/src/onchain.rs) (`SessionDeadlines`, `confirmed_session`), [enrollment/status](../../bins/solana-confidential-compute-sidecar/src/server.rs) (`attest_current_key`, `status_handler`), and [renewal](../../bins/solana-confidential-compute-sidecar/src/heartbeat.rs) (`poll_once`, `with_renewal_buffer_seconds`). Source and native validation do not establish fresh hardware enrollment, real SBF cryptographic execution, or deployment.
