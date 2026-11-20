//! Auto Switch state machine
//! Manages the handoff logic between Linux and Samsung phone

#![allow(dead_code)] // State machine scaffolding for call and multi-device handoff.
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::ble::coc_session::REASON_CALL;
use crate::ble::BleAdvEvent;
use crate::protocol::AudioState;
use crate::rfcomm::RfcommEvent;

/// Bound on a call-reason response the daemon still expects. [FR-017]
const CALL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// Why a Buds switch is requested. [FR-017]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchReason {
    Media,
    Call,
}

impl SwitchReason {
    /// Maps the protocol reason byte; only the call reason is not media.
    /// [FR-017]
    pub fn from_byte(reason: u8) -> Self {
        if reason == REASON_CALL {
            Self::Call
        } else {
            Self::Media
        }
    }
}

/// A call-reason response the daemon still expects. [FR-017]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingCallResponse {
    adv_id: u16,
    address: [u8; 6],
    since: Instant,
}

/// Call policy for handoff requests.
///
/// [FR-017] An active HFP call blocks media-reason requests, while call-reason
/// requests always proceed. Call state is entered on a call-reason request from
/// the phone and left when the phone reports the call ended, so a lost response
/// cannot lock media behind a blanket timer. A response is classified as
/// call-reason only when it matches the pending call-reason exchange; a
/// media-reason response never clears the guard.
#[derive(Debug)]
pub struct CallGuard {
    call_active: bool,
    pending: Option<PendingCallResponse>,
    response_timeout: Duration,
}

impl Default for CallGuard {
    fn default() -> Self {
        Self {
            call_active: false,
            pending: None,
            response_timeout: CALL_RESPONSE_TIMEOUT,
        }
    }
}

impl CallGuard {
    /// True while an HFP call owns the Buds.
    pub fn call_active(&self) -> bool {
        self.call_active
    }

    /// Marks a call active on a call-reason request from the phone.
    pub fn call_started(&mut self) {
        self.call_active = true;
    }

    /// Clears the call state when the phone reports the call ended.
    pub fn call_ended(&mut self) {
        self.call_active = false;
        self.pending = None;
    }

    /// Records that the daemon asked for the Buds for a call.
    pub fn expect_call_response(&mut self, adv_id: u16, address: [u8; 6], now: Instant) {
        self.pending = Some(PendingCallResponse {
            adv_id,
            address,
            since: now,
        });
    }

    /// Classifies a response and clears a matching call exchange.
    ///
    /// Returns [`SwitchReason::Call`] only for the response to a call-reason
    /// request; every other response is media, so it cannot clear the call
    /// guard. [FR-017]
    pub fn on_response(&mut self, adv_id: u16, address: [u8; 6], now: Instant) -> SwitchReason {
        let Some(pending) = self.pending else {
            return SwitchReason::Media;
        };
        if pending.adv_id == adv_id && pending.address == address {
            self.pending = None;
            return SwitchReason::Call;
        }
        if now.duration_since(pending.since) >= self.response_timeout {
            self.pending = None;
        }
        SwitchReason::Media
    }

    /// True when a media-reason request must be suppressed.
    pub fn blocks_media(&self) -> bool {
        self.call_active
    }
}

/// Current handoff state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffState {
    /// Linux is the active audio source
    LinuxActive,
    /// Phone is the active audio source
    PhoneActive,
    /// Handoff in progress (Linux -> Phone)
    HandingOffToPhone,
    /// Handoff in progress (Phone -> Linux)
    HandingOffToLinux,
    /// Idle, no active connection
    Idle,
}

/// Configuration for the handoff state machine
#[derive(Debug, Clone)]
pub struct HandoffConfig {
    pub phone_address: String,
    pub buds_address: String,
    pub auto_switch_enabled: bool,
    pub priority: DevicePriority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePriority {
    PhoneWins,
    LinuxWins,
    FirstComeFirstServed,
}

/// Auto Switch state machine
pub struct HandoffStateMachine {
    state: HandoffState,
    config: HandoffConfig,
    local_media_playing: bool,
    phone_audio_active: bool,
    phone_handoff_request: bool,
}

impl HandoffStateMachine {
    pub fn new(config: HandoffConfig) -> Self {
        Self {
            state: HandoffState::Idle,
            config,
            local_media_playing: false,
            phone_audio_active: false,
            phone_handoff_request: false,
        }
    }

    pub fn on_ble_event(&mut self, event: &BleAdvEvent) -> Option<HandoffAction> {
        if event.address != self.config.phone_address && event.address != self.config.buds_address {
            return None;
        }

        match event.audio_state {
            AudioState::Streaming => {
                if event.address == self.config.phone_address {
                    self.phone_audio_active = true;
                    if self.state == HandoffState::LinuxActive && self.config.auto_switch_enabled {
                        return Some(HandoffAction::YieldToPhone);
                    }
                }
            }
            AudioState::Idle => {
                if event.address == self.config.phone_address {
                    self.phone_audio_active = false;
                }
            }
            AudioState::Disconnected => {
                if event.address == self.config.buds_address {
                    self.state = HandoffState::Idle;
                }
            }
        }

        None
    }

    pub fn on_rfcomm_event(&mut self, event: &RfcommEvent) -> Option<HandoffAction> {
        match event {
            RfcommEvent::Received { address: _, data } => {
                if data.len() >= 4 {
                    let app_id = data[0];
                    let app_seq = data[1];
                    let cmd_type = data[2];

                    if cmd_type == 1 && app_id == 1 {
                        self.phone_handoff_request = true;
                        return Some(HandoffAction::YieldToPhone);
                    }

                    if cmd_type == 3 && app_seq == 10 {
                        return Some(HandoffAction::PhoneReady);
                    }
                }
                None
            }
            RfcommEvent::Connected { .. } => {
                info!("RFCOMM connected, handoff channel active");
                self.state = HandoffState::Idle;
                None
            }
            RfcommEvent::Disconnected { .. } => {
                warn!("RFCOMM disconnected");
                self.phone_handoff_request = false;
                None
            }
        }
    }

    pub fn on_local_media_start(&mut self) -> Option<HandoffAction> {
        self.local_media_playing = true;

        if self.config.auto_switch_enabled && !self.phone_audio_active {
            self.state = HandoffState::HandingOffToLinux;
            return Some(HandoffAction::ClaimBuds);
        }

        None
    }

    pub fn on_local_media_stop(&mut self) -> Option<HandoffAction> {
        self.local_media_playing = false;

        if self.state == HandoffState::LinuxActive {
            self.state = HandoffState::Idle;
        }

        None
    }

    pub fn on_handoff_complete(&mut self, to_linux: bool) {
        if to_linux {
            self.state = HandoffState::LinuxActive;
            info!("Handoff complete: Linux is now active");
        } else {
            self.state = HandoffState::PhoneActive;
            info!("Handoff complete: Phone is now active");
        }
    }
}

/// Actions the daemon should take during a handoff
#[derive(Debug, Clone)]
pub enum HandoffAction {
    YieldToPhone,
    ClaimBuds,
    PhoneReady,
    SetSeamless(bool),
    SendHandoffCommand(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUDS: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    #[test]
    fn an_active_call_blocks_media_reason_only() {
        let mut guard = CallGuard::default();
        guard.call_started();
        assert!(guard.blocks_media());
        assert_eq!(guard.on_response(1, BUDS, Instant::now()), SwitchReason::Media);
        assert!(guard.blocks_media());
    }

    #[test]
    fn a_media_response_does_not_clear_the_guard() {
        let now = Instant::now();
        let mut guard = CallGuard::default();
        guard.call_started();
        guard.expect_call_response(0x1234, BUDS, now);
        assert_eq!(guard.on_response(0x9999, BUDS, now), SwitchReason::Media);
        assert!(guard.blocks_media());
    }

    #[test]
    fn a_call_response_is_scoped_to_its_exchange() {
        let now = Instant::now();
        let mut guard = CallGuard::default();
        guard.expect_call_response(0x1234, BUDS, now);
        assert_eq!(
            guard.on_response(0x1234, BUDS, now),
            SwitchReason::Call
        );
        assert_eq!(
            guard.on_response(0x1234, BUDS, now),
            SwitchReason::Media,
            "the pending call exchange is consumed by its response"
        );
    }

    #[test]
    fn a_lost_call_response_does_not_lock_media() {
        let now = Instant::now();
        let mut guard = CallGuard::default();
        guard.expect_call_response(7, BUDS, now);
        assert!(!guard.blocks_media());
    }

    #[test]
    fn the_call_ends_on_the_phone_signal() {
        let mut guard = CallGuard::default();
        guard.call_started();
        guard.call_ended();
        assert!(!guard.blocks_media());
    }
}

