output "project" {
  description = "GCP project ID."
  value       = var.project
}

output "project_id" {
  description = "GCP project ID for the demo scripts."
  value       = var.project
}

output "solana_rpc_url" {
  description = "Public Solana RPC URL for the manual demo helper."
  value       = var.rpc_url
}

output "deployment_mode" {
  description = "Selected native SNP or launcher-managed Confidential Space path."
  value       = var.provider_config.deployment_mode
}

output "runtime_service_account" {
  description = "Dedicated account; scope any private registry permission to this account and workload repository."
  value       = google_service_account.demo.email
}

output "verifier_program_id" {
  description = "Explicit verifier program public key for the selected cluster."
  value       = var.verifier_program_id
}

output "consumer_program_id" {
  description = "Optional consumer program public key, or an empty string."
  value       = var.consumer_program_id
}

output "zone" {
  description = "Confidential VM zone."
  value       = google_compute_instance.demo.zone
}

output "instance_name" {
  description = "Instance to connect to with gcloud compute ssh --tunnel-through-iap."
  value       = google_compute_instance.demo.name
}

output "external_ip" {
  description = "Ephemeral egress IP; inbound SSH is restricted to IAP."
  value       = google_compute_instance.demo.network_interface[0].access_config[0].nat_ip
}
