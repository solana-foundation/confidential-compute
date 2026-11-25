terraform {
  required_version = ">= 1.9.0, < 2.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "8.12.0"
    }
  }
  # Local state is intentional. Do not put credentials or payer keys in Terraform.
}

provider "google" {
  project = var.project
  region  = var.region
  zone    = var.zone
}
