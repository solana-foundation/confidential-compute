# Nitro probe host access (#299)

The hardware probe requires an operator-provisioned Nitro host: active Docker
and allocator services, allocated spare CPUs/memory, Docker access, and read/write
Nitro device and runtime-directory access through the host's docker/ne groups.
Group access requires a fresh login. Docker access grants host root authority;
grant it only to trusted operators. Follow the installed Nitro CLI package's
permission policy. The probe now checks access and exits with a diagnostic when
prerequisites are missing; it does not provision the host or free resources by
terminating other enclaves.

Previous versions widened socket/device/directory permissions persistently.
Updating the script does not repair an already affected host. Its operator must
restore permissions from the host/package policy and review local access before
running workloads. This change supplies no permission-changing repair commands.

Validation uses static source checks and a controlled unavailable-Docker command
double. No Nitro hardware, host permission changes, or authentic attestation were
exercised by these tests.
