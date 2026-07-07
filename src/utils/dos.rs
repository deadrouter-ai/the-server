use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const SUBNET_RATE_LIMIT: usize = 1000;
const SUBNET_RATE_WINDOW: Duration = Duration::from_secs(60);
const SUBNET_BAN_DURATION: Duration = Duration::from_secs(5 * 60);

const IP_RATE_LIMIT: usize = 100;
const IP_RATE_WINDOW: Duration = Duration::from_secs(60);
const IP_BAN_DURATIONS: &[Duration] = &[
    Duration::from_secs(60),               // 1st violation: 1 minute
    Duration::from_secs(5 * 60),           // 2nd violation: 5 minutes
    Duration::from_secs(60 * 60),          // 3rd violation: 1 hour
    Duration::from_secs(24 * 60 * 60),     // 4th violation: 1 day
    Duration::from_secs(7 * 24 * 60 * 60), // 5th+ violation: 7 days
];

#[derive(Clone, PartialEq, Eq, Hash)]
struct Subnet([u8; 3]);

struct SubnetState {
    requests: VecDeque<Instant>,
    banned_until: Option<Instant>,
}

struct IpState {
    requests: VecDeque<Instant>,
    violations: usize,
    banned_until: Option<Instant>,
    active_connections: u32,
}

pub struct ConnectionGuard {
    dos: std::sync::Arc<DosProtection>,
    ipv4: Ipv4Addr,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.dos.decrement_connection(self.ipv4);
    }
}

pub struct DosProtection {
    subnets: Mutex<HashMap<Subnet, SubnetState>>,
    ips: Mutex<HashMap<Ipv4Addr, IpState>>,
    global_connections: std::sync::atomic::AtomicU32,
}

impl Default for DosProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl DosProtection {
    pub fn new() -> Self {
        Self {
            subnets: Mutex::new(HashMap::new()),
            ips: Mutex::new(HashMap::new()),
            global_connections: std::sync::atomic::AtomicU32::new(0),
        }
    }

    pub fn try_acquire_connection(self: &std::sync::Arc<Self>, ip: IpAddr) -> Option<ConnectionGuard> {
        let ipv4 = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => v6.to_ipv4_mapped()?,
        };

        if self.global_connections.load(std::sync::atomic::Ordering::Relaxed) >= 15000 {
            return None;
        }

        let mut ips = self.ips.lock().unwrap();
        let state = ips.entry(ipv4).or_insert_with(|| IpState {
            requests: VecDeque::new(),
            violations: 0,
            banned_until: None,
            active_connections: 0,
        });

        if state.active_connections >= 25 {
            return None;
        }

        state.active_connections += 1;
        self.global_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(ConnectionGuard {
            dos: self.clone(),
            ipv4,
        })
    }

    pub(crate) fn decrement_connection(&self, ipv4: Ipv4Addr) {
        self.global_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut ips) = self.ips.lock()
            && let Some(state) = ips.get_mut(&ipv4) {
                state.active_connections = state.active_connections.saturating_sub(1);
            }
    }

    /// Returns `Ok(())` if allowed, `Err(retry_after_secs)` if rate limited or banned.
    pub fn check_request(&self, ip: IpAddr) -> Result<(), u64> {
        let ipv4 = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => {
                // Try to extract mapped IPv4, otherwise reject (must support ONLY ipv4).
                if let Some(v4) = v6.to_ipv4_mapped() {
                    v4
                } else {
                    // Reject pure IPv6 immediately with a long retry to discourage
                    return Err(3600);
                }
            }
        };

        let now = Instant::now();
        let subnet = Subnet([ipv4.octets()[0], ipv4.octets()[1], ipv4.octets()[2]]);

        // 1. Check Subnet (Short term, permissive)
        {
            let mut subnets = self.subnets.lock().unwrap();
            let state = subnets.entry(subnet.clone()).or_insert_with(|| SubnetState {
                requests: VecDeque::new(),
                banned_until: None,
            });

            if let Some(ban_end) = state.banned_until {
                if now < ban_end {
                    return Err((ban_end - now).as_secs().max(1));
                } else {
                    state.banned_until = None;
                }
            }

            while let Some(&t) = state.requests.front() {
                if now.duration_since(t) > SUBNET_RATE_WINDOW {
                    state.requests.pop_front();
                } else {
                    break;
                }
            }

            state.requests.push_back(now);

            if state.requests.len() > SUBNET_RATE_LIMIT {
                let ban_end = now + SUBNET_BAN_DURATION;
                state.banned_until = Some(ban_end);
                state.requests.clear();
                return Err(SUBNET_BAN_DURATION.as_secs());
            }
        }

        // 2. Check IP (Strict, escalating bans)
        {
            let mut ips = self.ips.lock().unwrap();
            let state = ips.entry(ipv4).or_insert_with(|| IpState {
                requests: VecDeque::new(),
                violations: 0,
                banned_until: None,
                active_connections: 0,
            });

            if let Some(ban_end) = state.banned_until {
                if now < ban_end {
                    return Err((ban_end - now).as_secs().max(1));
                } else {
                    state.banned_until = None;
                }
            }

            while let Some(&t) = state.requests.front() {
                if now.duration_since(t) > IP_RATE_WINDOW {
                    state.requests.pop_front();
                } else {
                    break;
                }
            }

            state.requests.push_back(now);

            if state.requests.len() > IP_RATE_LIMIT {
                let ban_idx = state.violations.min(IP_BAN_DURATIONS.len() - 1);
                let ban_duration = IP_BAN_DURATIONS[ban_idx];
                state.violations += 1;
                
                let ban_end = now + ban_duration;
                state.banned_until = Some(ban_end);
                state.requests.clear();
                return Err(ban_duration.as_secs());
            }
        }

        Ok(())
    }
}
