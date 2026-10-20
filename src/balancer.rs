use crate::config::domain_fail_remaining;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use std::collections::HashMap;

// Порт proxy/balancer.py::_Balancer + health-приоритизация.
//
// Домены делятся на два яруса: пользовательские (priority, идут первыми)
// и авто-пул (остальные). Домены в health-кулдауне отодвигаются в конец,
// чтобы мёртвые адреса не съедали время подключения.
pub struct Balancer {
    domains: Vec<String>,
    /// сколько первых элементов `domains` — пользовательские (приоритетные)
    priority_count: usize,
    dc_to_domain: HashMap<i32, String>,
}

pub static BALANCER: Lazy<RwLock<Balancer>> = Lazy::new(|| RwLock::new(Balancer::new()));

fn is_healthy(domain: &str) -> bool {
    domain_fail_remaining(domain) == std::time::Duration::ZERO
}

impl Balancer {
    pub fn new() -> Self {
        Self {
            domains: Vec::new(),
            priority_count: 0,
            dc_to_domain: HashMap::new(),
        }
    }

    pub fn update_domains_list(&mut self, domains_list: &[String]) {
        self.update_domains_list_with_priority(0, domains_list);
    }

    pub fn update_domains_list_with_priority(&mut self, priority_count: usize, domains_list: &[String]) {
        // Оригинал: if Counter(self.domains) == Counter(domains_list): return.
        // Отсортированное сравнение эквивалентно сравнению мультимножеств.
        // Порядок и priority_count тоже учитываем: если ярусы меняются —
        // перестраиваем.
        let mut current_sorted = self.domains.clone();
        current_sorted.sort();
        let mut new_sorted = domains_list.to_vec();
        new_sorted.sort();

        if current_sorted == new_sorted && self.priority_count == priority_count {
            return;
        }

        if domains_list.is_empty() {
            return;
        }

        self.domains = domains_list.to_vec();
        self.priority_count = priority_count.min(self.domains.len());
        let mut rng = rand::thread_rng();

        self.dc_to_domain.clear();
        for dc_id in [1, 2, 3, 4, 5, 203] {
            if let Some(domain) = self.domains.choose(&mut rng) {
                self.dc_to_domain.insert(dc_id, domain.clone());
            }
        }
    }

    pub fn update_domain_for_dc(&mut self, dc_id: i32, domain: &str) -> bool {
        if self.dc_to_domain.get(&dc_id).map(|s| s.as_str()) == Some(domain) {
            return false;
        }
        self.dc_to_domain.insert(dc_id, domain.to_string());
        true
    }

    /// Порядок попыток для DC: закреплённый домен, затем приоритетные
    /// (пользовательские), затем авто-пул; домены в кулдауне — в конец.
    pub fn get_domains_for_dc(&self, dc_id: i32) -> Vec<String> {
        let mut result = Vec::new();
        let current_domain = self.dc_to_domain.get(&dc_id).cloned();

        if let Some(ref d) = current_domain {
            if is_healthy(d) {
                result.push(d.clone());
            }
        }

        let mut priority: Vec<String> = Vec::new();
        let mut rest: Vec<String> = Vec::new();
        let mut cooling: Vec<(std::time::Duration, String)> = Vec::new();

        for (i, d) in self.domains.iter().enumerate() {
            if Some(d) == current_domain.as_ref() {
                continue;
            }
            if !is_healthy(d) {
                cooling.push((domain_fail_remaining(d), d.clone()));
                continue;
            }
            if i < self.priority_count {
                priority.push(d.clone());
            } else {
                rest.push(d.clone());
            }
        }

        let mut rng = rand::thread_rng();
        priority.shuffle(&mut rng);
        rest.shuffle(&mut rng);
        result.extend(priority);
        result.extend(rest);

        // Кулдаун-домены — последним шансом, от «менее плохих» к худшим.
        cooling.sort_by(|a, b| a.0.cmp(&b.0));
        result.extend(cooling.into_iter().map(|(_, d)| d));

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{clear_domain_fail, mark_domain_fail};

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn priority_domains_come_first() {
        let mut b = Balancer::new();
        b.update_domains_list_with_priority(2, &v(&["u1.com", "u2.com", "a1.com", "a2.com"]));
        let order = b.get_domains_for_dc(2);
        assert_eq!(order.len(), 4);
        // закреплённый домен всегда первый
        let pinned = b.dc_to_domain.get(&2).cloned().unwrap();
        assert_eq!(order[0], pinned);
        // среди остальных приоритетные встречаются раньше авто-пула:
        // проверяем, что множество первых двух не хуже «приоритет+возможно pinned»
        let idx_u1 = order.iter().position(|d| d == "u1.com").unwrap();
        let idx_u2 = order.iter().position(|d| d == "u2.com").unwrap();
        let idx_a1 = order.iter().position(|d| d == "a1.com").unwrap();
        let idx_a2 = order.iter().position(|d| d == "a2.com").unwrap();
        let max_user = idx_u1.max(idx_u2);
        let min_auto = idx_a1.min(idx_a2);
        if pinned != "u1.com" && pinned != "u2.com" {
            assert!(max_user < min_auto, "user domains must precede auto pool");
        }
    }

    #[test]
    fn cooling_domains_move_to_back() {
        let mut b = Balancer::new();
        b.update_domains_list_with_priority(0, &v(&["x1.com", "x2.com", "x3.com"]));
        b.update_domain_for_dc(2, "x1.com");
        mark_domain_fail("x1.com");
        mark_domain_fail("x2.com");
        let order = b.get_domains_for_dc(2);
        assert_eq!(order[0], "x3.com");
        assert!(order[1] == "x1.com" || order[1] == "x2.com");
        clear_domain_fail("x1.com");
        clear_domain_fail("x2.com");
    }

    #[test]
    fn domain_fail_escalates_and_clears() {
        assert_eq!(domain_fail_remaining("q.example.com"), std::time::Duration::ZERO);
        mark_domain_fail("q.example.com");
        let r1 = domain_fail_remaining("q.example.com");
        assert!(r1 > std::time::Duration::ZERO && r1 <= std::time::Duration::from_secs(60));
        clear_domain_fail("q.example.com");
        assert_eq!(domain_fail_remaining("q.example.com"), std::time::Duration::ZERO);
    }
}
