//! Sliding time windows driven by packet timestamps.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::Duration;

use crate::time::Timestamp;

/// Hard cap on events remembered per window, bounding memory under floods.
pub const MAX_EVENTS: usize = 65_536;

/// Counts events inside a sliding window.
#[derive(Debug, Clone)]
pub struct EventWindow {
    span: Duration,
    events: VecDeque<Timestamp>,
}

impl EventWindow {
    /// Window covering the last `span`.
    pub fn new(span: Duration) -> Self {
        Self {
            span,
            events: VecDeque::new(),
        }
    }

    /// Records an event at `ts` and returns the count inside the window.
    pub fn record(&mut self, ts: Timestamp) -> usize {
        self.expire(ts);
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(ts);
        self.events.len()
    }

    /// Drops events older than the window relative to `now`.
    pub fn expire(&mut self, now: Timestamp) {
        let cutoff = now.minus(self.span);
        while self.events.front().is_some_and(|&t| t < cutoff) {
            self.events.pop_front();
        }
    }

    /// Events currently inside the window.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// True if no events are inside the window.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// Counts distinct keys seen inside a sliding window.
#[derive(Debug, Clone)]
pub struct DistinctWindow<K> {
    span: Duration,
    events: VecDeque<(Timestamp, K)>,
    counts: HashMap<K, usize>,
}

impl<K: Hash + Eq + Clone> DistinctWindow<K> {
    /// Window covering the last `span`.
    pub fn new(span: Duration) -> Self {
        Self {
            span,
            events: VecDeque::new(),
            counts: HashMap::new(),
        }
    }

    /// Records `key` at `ts` and returns the number of distinct keys in the window.
    pub fn record(&mut self, ts: Timestamp, key: K) -> usize {
        self.expire(ts);
        if self.events.len() >= MAX_EVENTS {
            self.pop_oldest();
        }
        *self.counts.entry(key.clone()).or_insert(0) += 1;
        self.events.push_back((ts, key));
        self.counts.len()
    }

    /// Drops events older than the window relative to `now`.
    pub fn expire(&mut self, now: Timestamp) {
        let cutoff = now.minus(self.span);
        while self.events.front().is_some_and(|(t, _)| *t < cutoff) {
            self.pop_oldest();
        }
    }

    fn pop_oldest(&mut self) {
        if let Some((_, key)) = self.events.pop_front() {
            if let Some(c) = self.counts.get_mut(&key) {
                *c -= 1;
                if *c == 0 {
                    self.counts.remove(&key);
                }
            }
        }
    }

    /// Distinct keys currently inside the window.
    pub fn distinct(&self) -> usize {
        self.counts.len()
    }

    /// Iterates over the distinct keys currently inside the window.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.counts.keys()
    }

    /// True if the window holds no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000;

    #[test]
    fn event_window_slides() {
        let mut w = EventWindow::new(Duration::from_secs(10));
        assert_eq!(w.record(Timestamp(0)), 1);
        assert_eq!(w.record(Timestamp(5 * S)), 2);
        assert_eq!(w.record(Timestamp(10 * S)), 3);
        assert_eq!(w.record(Timestamp(11 * S)), 3);
        w.expire(Timestamp(100 * S));
        assert!(w.is_empty());
    }

    #[test]
    fn distinct_window_counts_keys() {
        let mut w = DistinctWindow::new(Duration::from_secs(10));
        assert_eq!(w.record(Timestamp(0), 22), 1);
        assert_eq!(w.record(Timestamp(S), 22), 1);
        assert_eq!(w.record(Timestamp(2 * S), 80), 2);
        assert_eq!(w.record(Timestamp(10 * S + 1), 443), 3);
        assert_eq!(w.record(Timestamp(11 * S + 1), 443), 2);
        assert_eq!(w.keys().count(), 2);
        w.expire(Timestamp(30 * S));
        assert!(w.is_empty());
        assert_eq!(w.distinct(), 0);
    }

    #[test]
    fn caps_memory() {
        let mut w = DistinctWindow::new(Duration::from_secs(1000));
        for i in 0..(MAX_EVENTS + 10) {
            w.record(Timestamp(0), i);
        }
        assert_eq!(w.distinct(), MAX_EVENTS);
    }
}
