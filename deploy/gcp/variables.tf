variable "project" {
  description = "Existing GCP project ID with Compute Engine and IAP APIs enabled."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project))
    error_message = "Provide a GCP project ID (not its display name or number)."
  }
}

variable "region" {
  description = "Region containing the supported SEV-SNP zone."
  type        = string
  default     = "us-central1"
  nullable    = false
}

variable "zone" {
  description = "N2D AMD Milan SEV-SNP zone. Availability and quota must be checked before applying."
  type        = string
  default     = "us-central1-c"
  nullable    = false
  validation {
    condition = contains([
      "asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c",
      "europe-west2-b", "europe-west2-c",
      "europe-west3-a", "europe-west3-b", "europe-west3-c",
      "europe-west4-a", "europe-west4-b", "europe-west4-c",
      "us-central1-a", "us-central1-b", "us-central1-c",
    ], var.zone)
    error_message = "Choose a documented N2D AMD Milan SEV-SNP zone."
  }
  validation {
    condition     = startswith(var.zone, "${var.region}-")
    error_message = "zone must belong to region."
  }
}

variable "machine_type" {
  description = "Predefined N2D type, constrained to at most 96 vCPUs for SEV-SNP."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^n2d-(standard|highmem|highcpu)-(2|4|8|16|32|48|64|80|96)$", var.machine_type))
    error_message = "Use a predefined N2D standard, highmem, or highcpu type with 2–96 vCPUs."
  }
}

variable "boot_image" {
  description = "Required operator-selected GCE image resource. Ubuntu for native_snp; confidential-space-images for confidential_space. No inferred manual-run image."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^projects/[^/[:space:]]+/global/images/[^[:space:]]+$", var.boot_image))
    error_message = "Provide an explicit projects/PROJECT/global/images/IMAGE or family/FAMILY resource."
  }
}

variable "container_image" {
  description = "Existing Confidential Space workload repository/image, without tag/digest; empty explicitly for native_snp. No image build or publication is performed."
  type        = string
  nullable    = false
  validation {
    condition     = var.container_image == "" || can(regex("^[a-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+$", var.container_image))
    error_message = "Use an existing registry/repository/image without a tag, digest, credentials or URL scheme, or empty for native_snp."
  }
}

variable "container_image_digest" {
  description = "Required exact sha256 workload digest for confidential_space; empty explicitly for native_snp. Obtain from the manually tested image's publisher."
  type        = string
  nullable    = false
  validation {
    condition     = var.container_image_digest == "" || can(regex("^sha256:[0-9a-f]{64}$", var.container_image_digest))
    error_message = "Supply sha256: plus 64 lowercase hex digits, or explicitly empty for native_snp."
  }
}

variable "provider_config" {
  description = "Required attestation path: native_snp + SEV_SNP, or confidential_space + SEV. This is runtime configuration, not the statically pinned Terraform provider version."
  type = object({
    deployment_mode            = string
    confidential_instance_type = string
  })
  nullable = false
  validation {
    condition = contains([
      "native_snp:SEV_SNP", "confidential_space:SEV"
    ], "${var.provider_config.deployment_mode}:${var.provider_config.confidential_instance_type}")
    error_message = "Use native_snp with SEV_SNP, or confidential_space with SEV. Confidential Space SEV_SNP and TDX are not provided by this example."
  }
  validation {
    condition = var.provider_config.deployment_mode == "native_snp" ? (
      var.container_image == "" && var.container_image_digest == "" && startswith(var.boot_image, "projects/ubuntu-os-cloud/global/images/")
      ) : (
      var.container_image != "" && var.container_image_digest != "" && startswith(var.boot_image, "projects/confidential-space-images/")
    )
    error_message = "native_snp requires a native Ubuntu image and explicitly empty container inputs; confidential_space requires a confidential-space-images image and both pinned container inputs."
  }
}

variable "source_ref" {
  description = "Required immutable full commit SHA in the public solana-foundation/confidential-compute repository, including the GCP demo example."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[0-9a-fA-F]{40}$", var.source_ref))
    error_message = "source_ref must be a full 40-character hexadecimal Git commit SHA."
  }
}

variable "rpc_url" {
  description = "Public, credential-free Solana RPC URL. For localnet use an address reachable from the VM, not localhost. Never include RPC tokens."
  type        = string
  default     = "https://api.devnet.solana.com"
  nullable    = false
  validation {
    condition     = can(regex("^https?://[^[:space:]@?#]+(/[^[:space:]?#]*)?$", var.rpc_url))
    error_message = "Use an HTTP(S) URL without userinfo, query tokens, fragments, or whitespace."
  }
}

variable "verifier_program_id" {
  description = "Explicit verifier program public key deployed on the selected Solana cluster."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[1-9A-HJ-NP-Za-km-z]{32,44}$", var.verifier_program_id))
    error_message = "Provide the verifier program's base58 public key."
  }
}

variable "consumer_program_id" {
  description = "Optional downstream consumer program public key. Empty disables consumer signing."
  type        = string
  default     = ""
  nullable    = false
  validation {
    condition     = var.consumer_program_id == "" || can(regex("^[1-9A-HJ-NP-Za-km-z]{32,44}$", var.consumer_program_id))
    error_message = "consumer_program_id must be empty or a base58 public key."
  }
}

variable "boot_disk_size_gb" {
  description = "Boot disk size in GiB, including Rust build artifacts."
  type        = number
  default     = 100
  nullable    = false
  validation {
    condition     = var.boot_disk_size_gb >= 50 && var.boot_disk_size_gb <= 65536 && floor(var.boot_disk_size_gb) == var.boot_disk_size_gb
    error_message = "boot_disk_size_gb must be an integer between 50 and 65536."
  }
}

variable "boot_disk_type" {
  description = "Persistent boot disk type."
  type        = string
  default     = "pd-balanced"
  nullable    = false
  validation {
    condition     = contains(["pd-balanced", "pd-ssd", "pd-standard"], var.boot_disk_type)
    error_message = "Use pd-balanced, pd-ssd, or pd-standard."
  }
}
