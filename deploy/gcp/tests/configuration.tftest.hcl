# All provider operations are mocked. These plans never authenticate or call GCP.
mock_provider "google" {}

variables {
  project                = "confidential-demo-fixture"
  source_ref             = "0000000000000000000000000000000000000000"
  verifier_program_id    = "11111111111111111111111111111111"
  machine_type           = "n2d-standard-4"
  boot_image             = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64"
  container_image        = ""
  container_image_digest = ""
  provider_config = {
    deployment_mode            = "native_snp"
    confidential_instance_type = "SEV_SNP"
  }
}

run "native_snp" {
  command = plan
  assert {
    condition = (
      google_compute_instance.demo.confidential_instance_config[0].confidential_instance_type == "SEV_SNP" &&
      google_compute_instance.demo.scheduling[0].on_host_maintenance == "TERMINATE" &&
      google_compute_instance.demo.boot_disk[0].initialize_params[0].image == var.boot_image &&
      strcontains(google_compute_instance.demo.metadata_startup_script, "SOLANA_CC_ENCLAVE_MODE=amd-sev-snp") &&
      length(google_project_iam_member.confidential_space_workload) == 0
    )
    error_message = "Native SNP must use the supplied image, SNP/TERMINATE, native bootstrap and no runtime project role."
  }
}

run "confidential_space" {
  command = plan
  variables {
    boot_image             = "projects/confidential-space-images/global/images/confidential-space-fixture"
    container_image        = "example.invalid/fixture/sidecar"
    container_image_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    provider_config = {
      deployment_mode            = "confidential_space"
      confidential_instance_type = "SEV"
    }
  }
  assert {
    condition = (
      google_compute_instance.demo.confidential_instance_config[0].confidential_instance_type == "SEV" &&
      google_compute_instance.demo.scheduling[0].on_host_maintenance == "MIGRATE" &&
      google_compute_instance.demo.boot_disk[0].initialize_params[0].image == var.boot_image &&
      google_compute_instance.demo.metadata_startup_script == null &&
      google_compute_instance.demo.shielded_instance_config[0].enable_secure_boot &&
      google_compute_instance.demo.metadata["tee-image-reference"] == "${var.container_image}@${var.container_image_digest}" &&
      google_compute_instance.demo.metadata["tee-env-SOLANA_CC_ENCLAVE_MODE"] == "gcp-confidential-space" &&
      google_compute_instance.demo.metadata["tee-env-SOLANA_CC_CONTAINER_IMAGE_DIGEST"] == var.container_image_digest &&
      google_compute_instance.demo.metadata["tee-env-SOLANA_CC_SOLANA_RPC_URL"] == var.rpc_url &&
      google_compute_instance.demo.metadata["tee-env-DRY_RUN"] == "true" &&
      google_project_iam_member.confidential_space_workload[0].role == "roles/confidentialcomputing.workloadUser"
    )
    error_message = "Confidential Space must launch the supplied pinned workload with the OIDC configuration; never use the Ubuntu bootstrap or imply SNP support."
  }
}

run "reject_confidential_space_snp" {
  command = plan
  variables {
    boot_image             = "projects/confidential-space-images/global/images/confidential-space-fixture"
    container_image        = "example.invalid/fixture/sidecar"
    container_image_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    provider_config = {
      deployment_mode            = "confidential_space"
      confidential_instance_type = "SEV_SNP"
    }
  }
  expect_failures = [var.provider_config]
}

run "reject_ubuntu_with_launcher_provider" {
  command = plan
  variables {
    container_image        = "example.invalid/fixture/sidecar"
    container_image_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    provider_config = {
      deployment_mode            = "confidential_space"
      confidential_instance_type = "SEV"
    }
  }
  expect_failures = [var.provider_config]
}
