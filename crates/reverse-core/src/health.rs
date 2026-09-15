use crate::model::{HealthState, PathHealth};

#[derive(Debug, Clone)]
pub struct HealthConfig {
    pub failure_threshold: u32,
    pub recovery_threshold: u32,
    pub failback_cooldown_secs: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            recovery_threshold: 2,
            failback_cooldown_secs: 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HealthStateMachine {
    config: HealthConfig,
}

impl HealthStateMachine {
    pub fn new(config: HealthConfig) -> Self {
        Self { config }
    }

    pub fn with_default_config() -> Self {
        Self::new(HealthConfig::default())
    }

    pub fn record_success(&self, health: &mut PathHealth, now_epoch_secs: u64) {
        health.consecutive_failures = 0;
        health.consecutive_successes += 1;
        health.last_check_epoch_secs = now_epoch_secs;
        health.link_up = true;

        match health.state {
            HealthState::Unknown => {
                health.state = HealthState::Healthy;
            }
            HealthState::Down => {
                if health.consecutive_successes >= self.config.recovery_threshold {
                    health.state = HealthState::Recovering;
                }
            }
            HealthState::Recovering => {
                if health.consecutive_successes > self.config.recovery_threshold {
                    health.state = HealthState::Healthy;
                }
            }
            HealthState::Degraded => {
                health.state = HealthState::Healthy;
            }
            HealthState::Healthy => {}
        }
    }

    pub fn record_failure(&self, health: &mut PathHealth, now_epoch_secs: u64) {
        health.consecutive_successes = 0;
        health.consecutive_failures += 1;
        health.last_check_epoch_secs = now_epoch_secs;

        match health.state {
            HealthState::Unknown => {
                health.state = HealthState::Down;
            }
            HealthState::Healthy => {
                if health.consecutive_failures >= self.config.failure_threshold {
                    health.state = HealthState::Degraded;
                }
            }
            HealthState::Degraded => {
                health.state = HealthState::Down;
            }
            HealthState::Recovering => {
                health.state = HealthState::Down;
            }
            HealthState::Down => {}
        }
    }

    pub fn is_available(&self, health: &PathHealth) -> bool {
        match health.state {
            HealthState::Healthy | HealthState::Recovering => true,
            HealthState::Unknown | HealthState::Degraded | HealthState::Down => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_state_transitions() {
        let sm = HealthStateMachine::with_default_config();
        let mut health = PathHealth::default();

        assert_eq!(health.state, HealthState::Unknown);

        // Success from unknown -> Healthy
        sm.record_success(&mut health, 100);
        assert_eq!(health.state, HealthState::Healthy);

        // 1 failure: stays healthy
        sm.record_failure(&mut health, 101);
        assert_eq!(health.state, HealthState::Healthy);

        // 2 failures: stays healthy
        sm.record_failure(&mut health, 102);
        assert_eq!(health.state, HealthState::Healthy);

        // 3 failures: reaches threshold -> Degraded
        sm.record_failure(&mut health, 103);
        assert_eq!(health.state, HealthState::Degraded);

        // 4th failure: goes to Down
        sm.record_failure(&mut health, 104);
        assert_eq!(health.state, HealthState::Down);
        assert!(!sm.is_available(&health));

        // 1 success: still down (needs recovery threshold)
        sm.record_success(&mut health, 105);
        assert_eq!(health.state, HealthState::Down);

        // 2nd success: goes to Recovering
        sm.record_success(&mut health, 106);
        assert_eq!(health.state, HealthState::Recovering);
        assert!(sm.is_available(&health));

        // 3rd success: fully recovered to Healthy
        sm.record_success(&mut health, 107);
        assert_eq!(health.state, HealthState::Healthy);
    }
}
