# ATLAS–Suricata Autoresearch Lab

A small, offline harness for testing Suricata rule changes against harmless,
synthetic HTTP traffic inspired by AI-security threat modeling.

## What it does

- Generates a local PCAP containing routine requests and fictional lab markers.
- Writes a local Suricata rule and a JSON manifest.
- Replays the PCAP through Suricata and reports true positives, false positives,
  false negatives, precision, and recall.
- Leaves ATLAS technique IDs unset until a user validates the mapping.

This project tests detection rules; it does not train Suricata or generate
real-world attack traffic. Suricata runs in offline PCAP mode. No packets are
sent to a network.

## Requirements

- Python 3.10+
- Suricata installed and available on `PATH`

## Setup and run

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
atlas-suricata-lab


Artifacts are written to artifacts/. Review the generated PCAP, rule, manifest,
and Suricata logs for each experiment.

Paired research workflow
Read program.md before connecting an agent. Keep the scenario proposer and
evaluator roles separate, preserve experiment artifacts, and require human
approval before deploying any rule. The baseline does not require an API key
or make external API calls.

Safety and limitations
The generated traffic uses documentation-only IP addresses and fictional paths; it is never transmitted.
The rule detects a lab marker, not a real attack or an ATLAS technique.
Results apply only to this synthetic corpus. They do not establish production detection quality.
Validate ATLAS mappings against current framework data before recording IDs.



The autoresearch pattern is to run bounded experiments, measure an explicit metric, and keep or reject changes based on results; this repository adapts that loop to offline rule regression testing. <citation src="1"></citation>