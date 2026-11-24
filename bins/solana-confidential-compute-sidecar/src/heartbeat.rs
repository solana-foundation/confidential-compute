//! Background slot monitoring and autonomous attestation renewal task.
//!
//! @spec SCC-SIDECAR-005

use std::{sync::Arc, time::Duration};
use tokio::time::sleep;

use crate::server::{attest_current_key, SidecarAppState};

pub struct HeartbeatDaemon {
    state: Arc<SidecarAppState>,
    poll_interval: Duration,
    renewal_buffer_slots: u64,
    renewal_buffer_seconds: u64,
}

impl HeartbeatDaemon {
    pub fn new(
        state: Arc<SidecarAppState>,
        poll_interval_secs: u64,
        renewal_buffer_slots: u64,
    ) -> Self {
        Self {
            state,
            poll_interval: Duration::from_secs(poll_interval_secs),
            renewal_buffer_slots,
            renewal_buffer_seconds: 60,
        }
    }

    /// Spawns the background heartbeat loop.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }

    async fn run(&self) {
        tracing::info!(
            interval_secs = self.poll_interval.as_secs(),
            buffer_slots = self.renewal_buffer_slots,
            "Autonomous attestation heartbeat daemon started"
        );

        loop {
            sleep(self.poll_interval).await;

            if let Err(error) = self.poll_once().await {
                tracing::warn!(%error, "Heartbeat deadline check or renewal failed");
            }
        }
    }

    /// Set the Unix renewal buffer independently of slot speed.
    pub fn with_renewal_buffer_seconds(mut self, seconds: u64) -> Self {
        self.renewal_buffer_seconds = seconds;
        self
    }

    /// One heartbeat iteration. Trusted Clock time, never host wall time, decides
    /// live renewal. Failed refresh leaves the old deadlines intact for retry.
    pub async fn poll_once(&self) -> Result<bool, crate::error::SidecarError> {
        let status = self.state.status.read().await.clone();
        let Some(expiry) = status.expires_slot else {
            // No local deadline means a failed first enrollment or an explicit
            // rotation. Retry at the normal poll interval instead of giving up:
            // returning early here leaves the sidecar permanently unattested,
            // which is the defect this branch fixes. The key is not rotated.
            self.trigger_renewal(0).await?;
            return Ok(true);
        };
        let renew = if self.state.onchain.is_dry_run() {
            expiry.saturating_sub(self.state.onchain.get_current_slot().await?)
                <= self.renewal_buffer_slots
        } else {
            let key = self.state.keys.read().await.pubkey();
            self.state
                .onchain
                .confirmed_session(&key)
                .await?
                .needs_renewal(self.renewal_buffer_slots, self.renewal_buffer_seconds)
        };
        if renew {
            self.trigger_renewal(0).await?;
        }
        Ok(renew)
    }

    async fn trigger_renewal(&self, _current_slot: u64) -> Result<(), crate::error::SidecarError> {
        let pubkey_before = self.state.keys.read().await.pubkey();
        let expires_slot = attest_current_key(&self.state).await?;
        let pubkey_after = self.state.keys.read().await.pubkey();
        if pubkey_before != pubkey_after {
            return Err(crate::error::SidecarError::KeyError(
                "heartbeat rotated the workload key".to_string(),
            ));
        }
        tracing::info!(
            new_expires_slot = expires_slot,
            "Autonomous attestation renewed for the current ephemeral key"
        );
        Ok(())
    }
}

/// Re-attest the current ephemeral key. The pubkey is unchanged.
/// @spec SCC-SIDECAR-005
pub async fn reattest_current_key(
    state: &SidecarAppState,
) -> Result<u64, crate::error::SidecarError> {
    let pubkey_before = state.keys.read().await.pubkey();
    let expires_slot = attest_current_key(state).await?;
    let pubkey_after = state.keys.read().await.pubkey();
    if pubkey_before != pubkey_after {
        return Err(crate::error::SidecarError::KeyError(
            "heartbeat rotated the workload key".to_string(),
        ));
    }
    Ok(expires_slot)
}
