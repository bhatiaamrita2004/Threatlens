// Maps the detection rules to MITRE ATT&CK techniques, so an analyst can see what a
// pattern looks like in attacker terms. This is a labelling aid, not proof of an attack.

export const ATTACK_BY_RULE = {
  repeated_failed_logins: {
    id: "T1110",
    name: "Brute Force",
    tactic: "Credential Access",
    url: "https://attack.mitre.org/techniques/T1110/",
  },
  many_ports_one_source: {
    id: "T1046",
    name: "Network Service Discovery",
    tactic: "Discovery",
    url: "https://attack.mitre.org/techniques/T1046/",
  },
  event_burst: {
    id: "T1595",
    name: "Active Scanning",
    tactic: "Reconnaissance",
    url: "https://attack.mitre.org/techniques/T1595/",
  },
  privilege_change: {
    id: "T1098",
    name: "Account Manipulation",
    tactic: "Persistence",
    url: "https://attack.mitre.org/techniques/T1098/",
  },
};

export function attackFor(ruleName) {
  return ATTACK_BY_RULE[ruleName] ?? null;
}