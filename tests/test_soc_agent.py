"""Offline tests for the agent's non-LLM logic. No API calls are made.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import soc_agent  # noqa: E402
from agents.tool_context import ToolContext  # noqa: E402

SAMPLE_EVE = str(ROOT / "examples" / "sample_eve.json")


def alert(src, dest):
    return json.dumps({"event_type": "alert", "src_ip": src, "dest_ip": dest})


class ValidateIpTests(unittest.TestCase):
    def test_accepts_ipv4_and_ipv6(self):
        self.assertEqual(soc_agent.validate_ip(" 8.8.8.8 "), "8.8.8.8")
        self.assertEqual(soc_agent.validate_ip("2001:4860:4860::8888"), "2001:4860:4860::8888")

    def test_rejects_non_addresses(self):
        for bad in ["", "8.8.8.8; rm -rf /", "8.8.8.8/24", "999.1.1.1", "example.com", "$(id)"]:
            with self.assertRaises(ValueError, msg=bad):
                soc_agent.validate_ip(bad)


class FindAlertsTests(unittest.TestCase):
    def write_log(self, lines):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        handle.write("\n".join(lines) + "\n")
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_sample_log_matches_both_directions(self):
        alerts, total, skipped = soc_agent.find_alerts("8.8.8.8", SAMPLE_EVE)
        self.assertEqual((len(alerts), total, skipped), (2, 2, 0))
        self.assertEqual(alerts[0]["alert"]["signature"], "LAB ICMP Ping Detected")

    def test_no_match(self):
        alerts, total, _ = soc_agent.find_alerts("1.1.1.1", SAMPLE_EVE)
        self.assertEqual((alerts, total), ([], 0))

    def test_skips_malformed_blank_and_non_alert_lines(self):
        path = self.write_log([
            alert("10.0.0.1", "8.8.8.8"),
            '{"event_type": "alert", "src_ip": "8.8.8.8", "dest',  # truncated write
            "",
            "[1, 2, 3]",
            json.dumps({"event_type": "flow", "src_ip": "8.8.8.8"}),
            alert("8.8.8.8", "10.0.0.1"),
        ])
        alerts, total, skipped = soc_agent.find_alerts("8.8.8.8", path)
        self.assertEqual((len(alerts), total, skipped), (2, 2, 1))

    def test_total_is_counted_before_the_cap(self):
        path = self.write_log([alert("8.8.8.8", f"10.0.0.{i}") for i in range(25)])
        alerts, total, _ = soc_agent.find_alerts("8.8.8.8", path, limit=10)
        self.assertEqual((len(alerts), total), (10, 25))
        self.assertEqual(alerts[-1]["dest_ip"], "10.0.0.24")


class AuditLogTests(unittest.TestCase):
    def test_records_are_appended(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "audit.jsonl")
            with mock.patch.object(soc_agent, "AUDIT_LOG", path):
                soc_agent.write_audit_record("block_ip", '{"ip_address":"8.8.8.8"}', "approved")
                soc_agent.write_audit_record("block_ip", '{"ip_address":"8.8.8.8"}', "rejected")

            with open(path) as file:
                records = [json.loads(line) for line in file]

        self.assertEqual([r["decision"] for r in records], ["approved", "rejected"])
        self.assertEqual(records[0]["tool"], "block_ip")
        self.assertTrue(records[0]["simulated"])
        self.assertIn("timestamp", records[0])
        self.assertIn("operator", records[0])


class ApprovalPromptTests(unittest.TestCase):
    def decide(self, typed):
        pending = mock.Mock(arguments='{"ip_address":"8.8.8.8"}')
        pending.name = "block_ip"
        with mock.patch("builtins.input", side_effect=typed), \
                mock.patch.object(soc_agent, "write_audit_record") as audit, \
                mock.patch("builtins.print"):
            approved = soc_agent.request_approval(pending)
        return approved, audit.call_args.args[2]

    def test_only_y_approves(self):
        self.assertEqual(self.decide(["y"]), (True, "approved"))
        self.assertEqual(self.decide([" Y "]), (True, "approved"))

    def test_everything_else_is_denied(self):
        for typed in (["n"], [""], ["yes"], ["approve"], EOFError):
            self.assertEqual(self.decide(typed), (False, "rejected"), msg=typed)


class ToolWiringTests(unittest.TestCase):
    def invoke(self, tool, arguments):
        payload = json.dumps(arguments)
        context = ToolContext(
            context=None, tool_name=tool.name, tool_call_id="test-call", tool_arguments=payload
        )
        with mock.patch("builtins.print"):
            return asyncio.run(tool.on_invoke_tool(context, payload))

    def test_block_ip_requires_approval_and_evidence_tool_does_not(self):
        self.assertIs(soc_agent.block_ip.needs_approval, True)
        self.assertIs(soc_agent.get_recent_alerts.needs_approval, False)

    def test_block_ip_is_described_and_reported_as_simulation(self):
        self.assertIn("SIMULATION", soc_agent.block_ip.description)
        output = self.invoke(soc_agent.block_ip, {"ip_address": "8.8.8.8"})
        self.assertIn("SIMULATION ONLY", output)
        self.assertIn("not blocked", output)

    def test_tools_reject_invalid_ip_arguments(self):
        for tool in (soc_agent.block_ip, soc_agent.get_recent_alerts):
            output = self.invoke(tool, {"ip_address": "8.8.8.8; iptables -F"})
            self.assertTrue(output.startswith("ERROR"), msg=output)

    def test_evidence_tool_reports_true_total(self):
        with mock.patch.object(soc_agent, "EVE_FILE", SAMPLE_EVE):
            output = json.loads(self.invoke(soc_agent.get_recent_alerts, {"ip_address": "8.8.8.8"}))
        self.assertEqual(output["total_matching_alerts"], 2)
        self.assertEqual(len(output["alerts"]), 2)


if __name__ == "__main__":
    unittest.main()
