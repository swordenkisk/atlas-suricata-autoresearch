#!/usr/bin/env python3
"""Generate harmless synthetic HTTP traffic and evaluate a local Suricata rule."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from scapy.all import Ether, IP, TCP, Raw, wrpcap

LAB_SID = 9900001
CLIENT_IP = "192.0.2.10"
SERVER_IP = "198.51.100.20"
HTTP_PORT = 8080

# These are fictional test markers, not exploits or real attack payloads.
SCENARIOS = [
    {"name": "routine_health_check", "path": "/health", "expected_alert": False},
    {"name": "routine_status_request", "path": "/api/v1/status", "expected_alert": False},
    {
        "name": "synthetic_ai_probe_marker",
        "path": "/lab/synthetic/ai-probe",
        "expected_alert": True,
    },
    {
        "name": "synthetic_model_access_marker",
        "path": "/lab/synthetic/model-access",
        "expected_alert": True,
    },
]


def build_lab(output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    packets = []
    samples = []

    for index, scenario in enumerate(SCENARIOS):
        source_port = 50000 + index
        client_seq = 1000 + index * 1000
        server_seq = 5000 + index * 1000

        request = (
            f"GET {scenario['path']} HTTP/1.1\r\n"
            "Host: lab.invalid\r\n"
            "User-Agent: atlas-suricata-lab/1.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")

        def packet(tcp: TCP, payload: bytes = b"") -> Any:
            frame = Ether() / IP(src=CLIENT_IP, dst=SERVER_IP) / tcp
            if payload:
                frame = frame / Raw(load=payload)
            frame.time = float(index * 2) + len(packets) * 0.001
            return frame

        # A minimal TCP handshake and HTTP exchange, written only to a local PCAP.
        packets.append(packet(TCP(sport=source_port, dport=HTTP_PORT,
                                  seq=client_seq, flags="S")))
        packets.append(packet(TCP(sport=HTTP_PORT, dport=source_port,
                                  seq=server_seq, ack=client_seq + 1, flags="SA")))
        packets.append(packet(TCP(sport=source_port, dport=HTTP_PORT,
                                  seq=client_seq + 1, ack=server_seq + 1, flags="A")))
        packets.append(packet(TCP(sport=source_port, dport=HTTP_PORT,
                                  seq=client_seq + 1, ack=server_seq + 1, flags="PA"),
                              request))
        packets.append(packet(TCP(sport=HTTP_PORT, dport=source_port,
                                  seq=server_seq + 1,
                                  ack=client_seq + 1 + len(request), flags="PA"),
                              b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))

        samples.append({
            **scenario,
            "source_port": source_port,
            "atlas_technique_id": None,
            "mapping_note": "Set an ATLAS ID only after validating it against current ATLAS data.",
        })

    pcap_path = output_dir / "synthetic-lab.pcap"
    rules_path = output_dir / "lab.rules"
    manifest_path = output_dir / "manifest.json"

    wrpcap(str(pcap_path), packets)
    rules_path.write_text(
        'alert http 192.0.2.0/24 any -> 198.51.100.0/24 8080 '
        '(msg:"LAB synthetic ATLAS-linked marker"; '
        'flow:established,to_server; http.uri; content:"/lab/synthetic/"; '
        f'sid:{LAB_SID}; rev:1;)\n',
        encoding="utf-8",
    )

    manifest = {
        "purpose": "Offline Suricata rule regression test; not an attack dataset.",
        "pcap": pcap_path.name,
        "rules": rules_path.name,
        "samples": samples,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def evaluate(output_dir: Path) -> dict[str, Any]:
    suricata = shutil.which("suricata")
    if not suricata:
        raise RuntimeError("Suricata was not found on PATH. Install it before evaluation.")

    manifest_path = output_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    pcap_path = output_dir / manifest["pcap"]
    rules_path = output_dir / manifest["rules"]
    log_dir = output_dir / "suricata-logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    command = [
        suricata, "-r", str(pcap_path), "-S", str(rules_path),
        "-l", str(log_dir),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            "Suricata evaluation failed.\n"
            f"Command: {' '.join(command)}\n"
            f"stderr:\n{result.stderr}"
        )

    eve_path = log_dir / "eve.json"
    if not eve_path.exists():
        raise RuntimeError(f"Suricata did not produce {eve_path}")

    expected_by_port = {
        sample["source_port"]: sample["expected_alert"]
        for sample in manifest["samples"]
    }
    detected_ports: set[int] = set()

    for line in eve_path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        alert = event.get("alert", {})
        if event.get("event_type") == "alert" and alert.get("signature_id") == LAB_SID:
            detected_ports.add(int(event.get("src_port", -1)))

    true_positives = sum(
        1 for port, expected in expected_by_port.items()
        if expected and port in detected_ports
    )
    false_negatives = sum(
        1 for port, expected in expected_by_port.items()
        if expected and port not in detected_ports
    )
    false_positives = sum(
        1 for port, expected in expected_by_port.items()
        if not expected and port in detected_ports
    )

    positive_count = true_positives + false_negatives
    precision_denominator = true_positives + false_positives

    return {
        "rule_sid": LAB_SID,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "recall": true_positives / positive_count if positive_count else 0.0,
        "precision": (
            true_positives / precision_denominator
            if precision_denominator else 0.0
        ),
        "pcap": str(pcap_path),
        "suricata_log_dir": str(log_dir),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build harmless synthetic traffic and test a local Suricata rule."
    )
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts"),
        help="Directory for PCAP, rule, manifest, and Suricata logs.",
    )
    args = parser.parse_args()

    try:
        build_lab(args.output)
        report = evaluate(args.output)
        print(json.dumps(report, indent=2))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
