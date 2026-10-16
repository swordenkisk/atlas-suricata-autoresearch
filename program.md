# Paired autoresearch protocol

## Roles

1. **Scenario proposer:** Suggests harmless, fictional HTTP observables and labels.
   Never create exploit payloads, malware, credential theft, evasion instructions,
   or traffic intended for a real target.
2. **Independent evaluator:** Runs the generated PCAP through Suricata offline,
   checks alerts against the manifest, and reports precision/recall plus the
   exact rule diff.

## Experiment loop

1. Keep each experiment bounded to one candidate rule change.
2. Generate only local PCAP artifacts using documentation-only IP ranges.
3. Run Suricata in offline PCAP mode; do not send packets to any network.
4. Compare candidate results with the baseline on the same manifest.
5. Keep a change only when it improves the stated metric without increasing
   false positives beyond the configured limit.
6. Record the rule diff, command, metrics, and scenario versions.
7. Require human review before any rule is deployed outside this lab.

## ATLAS mapping

Use MITRE ATLAS as a threat-modeling reference. Confirm technique identifiers
against current ATLAS data before assigning them. A matching HTTP marker is
only a test observable; it is not proof that the underlying ATLAS technique
occurred.
