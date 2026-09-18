use crate::error::CoreError;
use crate::model::{ActualState, DesiredState, RpdbRule, StateDiff};

pub struct RoutePlanner;

impl RoutePlanner {
    pub fn plan_diff(actual: &ActualState, desired: &DesiredState) -> Result<StateDiff, CoreError> {
        Self::validate_desired_state(desired)?;

        let mut diff = StateDiff::default();

        // 1. Calculate routes to add
        for d_route in &desired.routes {
            if !actual.routes.iter().any(|a| a == d_route) {
                diff.routes_to_add.push(d_route.clone());
            }
        }

        // 2. Calculate routes to remove (only routes in the owned table that are not in desired)
        for a_route in &actual.routes {
            if a_route.table == actual.allocated_table
                && !desired.routes.iter().any(|d| d == a_route)
            {
                diff.routes_to_remove.push(a_route.clone());
            }
        }

        // 3. Calculate RPDB rules to add
        for d_rule in &desired.rules {
            if !actual.rules.iter().any(|a| a == d_rule) {
                diff.rules_to_add.push(d_rule.clone());
            }
        }

        // 4. Calculate RPDB rules to remove (only rules in our owned table/priority range)
        for a_rule in &actual.rules {
            if a_rule.table == actual.allocated_table
                && a_rule.priority == actual.rule_priority
                && !desired.rules.iter().any(|d| d == a_rule)
            {
                diff.rules_to_remove.push(a_rule.clone());
            }
        }

        Ok(diff)
    }

    pub fn validate_desired_state(desired: &DesiredState) -> Result<(), CoreError> {
        // Critical safety rule: Custom table MUST NEVER contain a default route!
        for route in &desired.routes {
            if route.destination.prefix_len() == 0 {
                return Err(CoreError::Planner(
                    "Safety violation: Table 52000 MUST NOT contain a default route (0.0.0.0/0 or ::/0)".into(),
                ));
            }

            // A more specific LAN route wins over a broader blacklist route
            // in Linux's FIB. Reject the configuration before it gets that
            // far; relying on firewall rule ordering alone leaves routing and
            // policy explanations inconsistent.
            if route.route_type == crate::model::RouteType::Unicast
                && desired.lan_interfaces.contains(&route.output_interface)
                && desired
                    .blacklist
                    .iter()
                    .any(|blocked| nets_overlap(*blocked, route.destination))
            {
                return Err(CoreError::Planner(format!(
                    "Safety violation: LAN route {} on {} overlaps blacklist",
                    route.destination, route.output_interface
                )));
            }
        }
        Ok(())
    }

    pub fn generate_desired_state(
        table_id: u32,
        rule_priority: u32,
        routes: Vec<crate::model::Route>,
        split_dns: Vec<(String, std::net::IpAddr)>,
    ) -> DesiredState {
        let rule = RpdbRule {
            priority: rule_priority,
            table: table_id,
        };

        DesiredState {
            routes,
            rules: vec![rule],
            dns_split_domains: split_dns,
            firewall_whitelist: vec![],
            wan_interface: None,
            lan_interfaces: vec![],
            blacklist: vec![],
        }
    }
}

fn nets_overlap(a: ipnet::IpNet, b: ipnet::IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Route, RouteType};

    #[test]
    fn test_reject_default_route_safety() {
        let default_route = Route {
            destination: "0.0.0.0/0".parse().unwrap(),
            output_interface: "eth1".into(),
            gateway: None,
            table: 52000,
            metric: None,
            route_type: RouteType::Unicast,
        };

        let desired = DesiredState {
            routes: vec![default_route],
            rules: vec![],
            dns_split_domains: vec![],
            firewall_whitelist: vec![],
            wan_interface: None,
            lan_interfaces: vec![],
            blacklist: vec![],
        };

        let res = RoutePlanner::validate_desired_state(&desired);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Safety violation"));
    }

    #[test]
    fn test_plan_diff_calculation() {
        let actual = ActualState {
            routes: vec![Route {
                destination: "10.0.0.0/24".parse().unwrap(),
                output_interface: "wlan1".into(),
                gateway: None,
                table: 52000,
                metric: None,
                route_type: RouteType::Unicast,
            }],
            rules: vec![RpdbRule {
                priority: 12000,
                table: 52000,
            }],
            allocated_table: 52000,
            rule_priority: 12000,
        };

        let desired = DesiredState {
            routes: vec![Route {
                destination: "10.0.0.0/24".parse().unwrap(),
                output_interface: "eth1".into(),
                gateway: None,
                table: 52000,
                metric: None,
                route_type: RouteType::Unicast,
            }],
            rules: vec![RpdbRule {
                priority: 12000,
                table: 52000,
            }],
            dns_split_domains: vec![],
            firewall_whitelist: vec![],
            wan_interface: None,
            lan_interfaces: vec![],
            blacklist: vec![],
        };

        let diff = RoutePlanner::plan_diff(&actual, &desired).unwrap();
        assert_eq!(diff.routes_to_remove.len(), 1);
        assert_eq!(diff.routes_to_remove[0].output_interface, "wlan1");
        assert_eq!(diff.routes_to_add.len(), 1);
        assert_eq!(diff.routes_to_add[0].output_interface, "eth1");
        assert!(diff.rules_to_add.is_empty());
        assert!(diff.rules_to_remove.is_empty());
    }

    #[test]
    fn rejects_more_specific_lan_route_inside_blacklisted_cidr() {
        let desired = DesiredState {
            routes: vec![Route {
                destination: "10.0.0.99/32".parse().unwrap(),
                output_interface: "eth0".into(),
                gateway: None,
                table: 52000,
                metric: None,
                route_type: RouteType::Unicast,
            }],
            rules: vec![],
            dns_split_domains: vec![],
            firewall_whitelist: vec![],
            wan_interface: Some("wlan1".into()),
            lan_interfaces: vec!["eth0".into()],
            blacklist: vec!["10.0.0.0/24".parse().unwrap()],
        };

        let error = RoutePlanner::validate_desired_state(&desired)
            .unwrap_err()
            .to_string();
        assert!(error.contains("overlaps blacklist"));
    }
}
