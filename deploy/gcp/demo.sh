#!/usr/bin/env bash
# Manual commands only. Merely reading this file or running check creates no VM.
set -euo pipefail

demo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$demo_dir/../.." && pwd)
artifact_dir=${SOLANA_CC_DEMO_ARTIFACTS:-"$demo_dir/artifacts"}

usage() {
    cat <<'EOF'
Usage: ./demo.sh COMMAND [helper arguments]
  check       Local Terraform/shell/unit checks; no plan, apply or cloud API
  init        Initialize Terraform with local state
  provision   Interactive Terraform apply (creates billable GCP resources)
  wait        Wait for native guest API, or CS VM RUNNING (not workload readiness)
  attest      Capture and locally verify a fresh hardware report in the VM
  fetch       Fetch report.bin, vcek.der and manifest.json to artifacts/
  verify      Verify fetched evidence locally, without cloud/RPC requests
  enroll      Build Mode A enrollment; --submit --payer GUEST_PATH sends it
  mode-a      Enrollment plus confirmed-record check (simulation by default)
  mode-b      Show the SNP Mode B packet-size blocker; never broadcasts
  status      Read sidecar status (does not imply successful enrollment)
  logs        Read guest bootstrap and sidecar logs
  ssh         Open an IAP/OS Login shell
  teardown    Interactive Terraform destroy
See README.md before provision, enrollment, or teardown.
EOF
}

tf() { terraform -chdir="$demo_dir" "$@"; }

load_instance() {
    project=$(tf output -raw project_id)
    zone=$(tf output -raw zone)
    instance=$(tf output -raw instance_name)
    deployment_mode=$(tf output -raw deployment_mode)
    [[ -n "$project" && -n "$zone" && -n "$instance" ]] || {
        echo 'Missing Terraform outputs. Provision first, using this state directory.' >&2
        exit 1
    }
}

remote() {
    local remote_command
    if [[ "$deployment_mode" != native_snp ]]; then
        echo 'SNP/SSH commands require native_snp. Confidential Space disables production SSH; use status/logs and the supplied workload runbook.' >&2
        return 2
    fi
    # gcloud transmits a shell command. Quote every argument, including user flags.
    printf -v remote_command '%q ' "$@"
    gcloud compute ssh "$instance" --project="$project" --zone="$zone" \
        --tunnel-through-iap --ssh-flag=-oConnectTimeout=10 --command="$remote_command"
}

guest_helper() { remote sudo -u confidential-compute /usr/local/bin/confidential-compute-gcp-demo "$@"; }

command=${1:-help}
if (( $# > 0 )); then shift; fi
case "$command" in
    help|-h|--help) usage ;;
    check)
        tf fmt -check
        tf init -backend=false -input=false
        tf validate
        # Only mock_provider fixtures; no project credentials or cloud requests.
        tf test -no-color
        if command -v tflint >/dev/null 2>&1; then
            tflint --chdir="$demo_dir"
        else
            echo 'tflint unavailable; skipped (not installed automatically).'
        fi
        bash -n "$demo_dir/demo.sh"
        shellcheck "$demo_dir/demo.sh"
        python3 -m unittest discover -s "$demo_dir/tests" -p 'test_*.py' -v
        ;;
    init) tf init -input=false "$@" ;;
    provision)
        tf init -input=false
        tf apply "$@"
        ;;
    teardown) tf destroy "$@" ;;
    verify)
        gcp_demo_bin=${SOLANA_CC_GCP_DEMO_BIN:-}
        if [[ -n ${gcp_demo_bin} ]]; then
            "$gcp_demo_bin" verify --artifacts "$artifact_dir" "$@"
        else
            cargo run --locked --manifest-path "$repo_dir/Cargo.toml" \
                -p solana-confidential-compute-sidecar --example gcp-demo -- verify --artifacts "$artifact_dir" "$@"
        fi
        ;;
    wait)
        boot_timeout=${BOOT_TIMEOUT_SECONDS:-1800}
        [[ "$boot_timeout" =~ ^[1-9][0-9]*$ ]] || {
            echo 'BOOT_TIMEOUT_SECONDS must be a positive integer.' >&2; exit 2;
        }
        load_instance
        deadline=$((SECONDS + boot_timeout))
        echo "Waiting for $instance (up to $boot_timeout seconds)..."
        until timeout 30s bash "$demo_dir/demo.sh" status >/dev/null 2>&1; do
            if (( SECONDS >= deadline )); then
                echo 'Guest not ready; run ./demo.sh logs. Build/SEV-SNP boot can be slow.' >&2
                exit 1
            fi
            sleep 10
        done
        # A healthy HTTP API proves startup, not registration or hardware verification.
        if [[ "$deployment_mode" == native_snp ]]; then
            echo 'Sidecar API is ready. Run attest to check actual hardware evidence.'
        else
            echo 'Confidential Space VM is RUNNING; workload readiness and attestation are unverified. Inspect logs and the supplied workload runbook.'
        fi
        ;;
    attest|fetch|enroll|mode-a|mode-b|status|logs|ssh)
        load_instance
        case "$command" in
            attest)
                guest_helper capture --rpc-url "$(tf output -raw solana_rpc_url)" \
                    --out-dir /var/lib/confidential-compute/demo "$@"
                ;;
            fetch)
                umask 077
                mkdir -p -- "$artifact_dir"
                for file in report.bin vcek.der manifest.json; do
                    # sudo reads only public evidence; no payer/key directory is copied.
                    remote sudo -u confidential-compute cat "/var/lib/confidential-compute/demo/$file" > "$artifact_dir/$file.part"
                    mv -- "$artifact_dir/$file.part" "$artifact_dir/$file"
                done
                echo "Fetched public evidence into $artifact_dir"
                ;;
            enroll|mode-a)
                guest_helper "$command" --rpc-url "$(tf output -raw solana_rpc_url)" \
                    --program-id "$(tf output -raw verifier_program_id)" "$@"
                ;;
            mode-b)
                consumer=$(tf output -raw consumer_program_id)
                [[ -n "$consumer" ]] || {
                    echo 'Set consumer_program_id in terraform.tfvars before mode-b.' >&2; exit 2;
                }
                guest_helper mode-b --rpc-url "$(tf output -raw solana_rpc_url)" \
                    --program-id "$(tf output -raw verifier_program_id)" \
                    --consumer-program-id "$consumer" "$@"
                ;;
            status)
                if [[ "$deployment_mode" == native_snp ]]; then
                    remote bash -c 'test -c /dev/sev-guest && systemctl is-active --quiet solana-confidential-compute-sidecar.service && curl --fail --silent --show-error --max-time 10 http://127.0.0.1:8080/v1/status'
                else
                    vm_status=$(gcloud compute instances describe "$instance" --project="$project" --zone="$zone" --format='value(status)')
                    echo "$vm_status"
                    [[ "$vm_status" == RUNNING ]]
                fi
                ;;
            logs)
                if [[ "$deployment_mode" == native_snp ]]; then
                    remote sudo journalctl --no-pager -n 150 -u google-startup-scripts.service -u solana-confidential-compute-sidecar.service
                else
                    gcloud compute instances get-serial-port-output "$instance" --project="$project" --zone="$zone"
                fi
                ;;
            ssh)
                [[ "$deployment_mode" == native_snp ]] || {
                    echo 'Production Confidential Space disables SSH. This example does not weaken debug policy or expose the signer.' >&2; exit 2;
                }
                gcloud compute ssh "$instance" --project="$project" --zone="$zone" --tunnel-through-iap "$@"
                ;;
        esac
        ;;
    *) usage >&2; exit 2 ;;
esac
