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
                    if matches!(
                        self.state,
                        HandoffState::LinuxActive | HandoffState::HandingOffToLinux
                    ) && self.config.auto_switch_enabled
                    {
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
        None
    }

    pub fn set_buds_connected(&mut self, connected: bool) {
        if connected {
            if self.state != HandoffState::HandingOffToPhone {
                self.state = HandoffState::LinuxActive;
            }
        } else if self.state == HandoffState::LinuxActive {
            self.state = HandoffState::Idle;
        }
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    use crate::protocol::{BleHeader, DeviceType};

    fn sample_config() -> HandoffConfig {
        HandoffConfig {
            phone_address: "EC:B5:50:10:4E:B0".into(),
            buds_address: "E8:C9:13:A1:B9:1C".into(),
            auto_switch_enabled: true,
            priority: DevicePriority::PhoneWins,
        }
    }

    fn sample_adv(address: &str, audio_state: AudioState) -> BleAdvEvent {
        BleAdvEvent {
            address: address.into(),
            address_type: bluer::AddressType::LePublic,
            rssi: -50,
            header: BleHeader {
                version: 0x02,
                subtype: 0x18,
                flags: 0x27,
            },
            device_type: DeviceType::Phone,
            context: None,
            audio_state,
            coc_psm: Some(0x0081),
            raw_data: vec![],
        }
    }

    #[test]
    fn yields_to_phone_when_linux_owns_buds_and_phone_streams() {
        let mut sm = HandoffStateMachine::new(sample_config());
        sm.set_buds_connected(true);
        // Even if local media stops later, Linux still holds the Buds connection.
        sm.on_local_media_stop();

        let ev = sample_adv("EC:B5:50:10:4E:B0", AudioState::Streaming);
        assert_eq!(sm.on_ble_event(&ev), Some(HandoffAction::YieldToPhone));
    }

    #[test]
    fn does_not_yield_when_buds_not_connected_to_linux() {
        let mut sm = HandoffStateMachine::new(sample_config());
        let ev = sample_adv("EC:B5:50:10:4E:B0", AudioState::Streaming);
        assert_eq!(sm.on_ble_event(&ev), None);
    }
}
