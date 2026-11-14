//! Auto Switch state machine
//! Manages the handoff logic between Linux and Samsung phone

#![allow(dead_code)] // State machine scaffolding for call and multi-device handoff.
use tracing::{info, warn};

use crate::ble::BleAdvEvent;
use crate::protocol::AudioState;
use crate::rfcomm::RfcommEvent;

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
