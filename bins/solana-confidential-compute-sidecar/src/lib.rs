//! Solana Confidential Compute Hardware Enclave Sidecar Daemon Library.
//!
//! @spec SCC-SIDECAR-001 through SCC-SIDECAR-006

pub mod attestation;
pub mod config;
pub mod control;
pub mod error;
pub mod heartbeat;
pub mod keys;
pub mod onchain;
pub mod server;
pub mod signing_policy;
pub mod tdx_enrolment;

pub use attestation::{AttestationProvider, AttestationReport};
pub use config::{EnclaveMode, SidecarConfig};
pub use error::SidecarError;
pub use heartbeat::{reattest_current_key, HeartbeatDaemon};
pub use keys::EphemeralKeyManager;
pub use onchain::{MockCluster, OnchainAttestor};
pub use server::{
    attest_current_key, create_router, rotate_zeroize_and_attest, validate_loopback_addr,
    SidecarAppState,
};
