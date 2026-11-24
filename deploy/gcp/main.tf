locals {
  confidential_space = var.provider_config.deployment_mode == "confidential_space"
  workload_environment = merge({
    SOLANA_CC_ENCLAVE_MODE           = "gcp-confidential-space"
    SOLANA_CC_BIND_ADDR              = "127.0.0.1:8080"
    SOLANA_CC_SOLANA_RPC_URL         = var.rpc_url
    SOLANA_CC_VERIFIER_PROGRAM_ID    = var.verifier_program_id
    SOLANA_CC_CONTAINER_IMAGE_DIGEST = var.container_image_digest
    DRY_RUN                          = "true"
    }, var.consumer_program_id == "" ? {} : {
    SOLANA_CC_ALLOWED_CONSUMER_PROGRAM_ID = var.consumer_program_id
  })
}

resource "google_compute_network" "demo" {
  name                    = "confidential-compute-gcp-demo"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "demo" {
  name          = "confidential-compute-gcp-demo"
  region        = var.region
  network       = google_compute_network.demo.id
  ip_cidr_range = "10.71.0.0/24"
}

# No public SSH or application ingress; IAP authorization and OS Login IAM are
# granted separately by the operator. Native SNP has no runtime project role;
# Confidential Space receives only its documented attestation role below.
resource "google_compute_firewall" "iap_ssh" {
  name                    = "confidential-compute-gcp-demo-iap-ssh"
  network                 = google_compute_network.demo.id
  direction               = "INGRESS"
  source_ranges           = ["35.235.240.0/20"]
  target_service_accounts = [google_service_account.demo.email]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_service_account" "demo" {
  account_id   = "confidential-compute-gcp-demo"
  display_name = "Solana Confidential Compute demo"
}

# The launcher must exchange evidence with Google Cloud Attestation. Native SNP
# needs no GCP API role. Registry access remains an operator prerequisite.
resource "google_project_iam_member" "confidential_space_workload" {
  count   = local.confidential_space ? 1 : 0
  project = var.project
  role    = "roles/confidentialcomputing.workloadUser"
  member  = "serviceAccount:${google_service_account.demo.email}"
}

resource "google_compute_instance" "demo" {
  name             = "confidential-compute-gcp-demo"
  zone             = var.zone
  machine_type     = var.machine_type
  min_cpu_platform = "AMD Milan"

  confidential_instance_config {
    confidential_instance_type = var.provider_config.confidential_instance_type
  }

  scheduling {
    on_host_maintenance = local.confidential_space ? "MIGRATE" : "TERMINATE"
    automatic_restart   = true
  }

  boot_disk {
    interface = "NVME"
    initialize_params {
      image = var.boot_image
      size  = var.boot_disk_size_gb
      type  = var.boot_disk_type
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.demo.id
    nic_type   = "GVNIC"
    # Ephemeral public IP provides outbound access for apt, GitHub and Solana.
    # The dedicated VPC's implied deny ingress still applies.
    access_config {}
  }

  service_account {
    email  = google_service_account.demo.email
    scopes = local.confidential_space ? ["https://www.googleapis.com/auth/cloud-platform"] : []
  }

  shielded_instance_config {
    enable_secure_boot          = local.confidential_space
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = merge({
    enable-oslogin         = local.confidential_space ? "FALSE" : "TRUE"
    block-project-ssh-keys = "TRUE"
    }, local.confidential_space ? merge({
      tee-image-reference = "${var.container_image}@${var.container_image_digest}"
    }, { for name, value in local.workload_environment : "tee-env-${name}" => value }
  ) : {})

  # Confidential Space's launcher starts the supplied workload. Running Ubuntu
  # package installation as a CS startup script would not produce that runtime.
  metadata_startup_script = local.confidential_space ? null : templatefile("${path.module}/startup.sh.tftpl", {
    source_ref_b64          = base64encode(lower(var.source_ref))
    rpc_url_b64             = base64encode(var.rpc_url)
    verifier_program_id_b64 = base64encode(var.verifier_program_id)
    consumer_program_id_b64 = base64encode(var.consumer_program_id)
  })

  depends_on = [google_compute_firewall.iap_ssh, google_project_iam_member.confidential_space_workload]
}
