import json
import os
import tempfile
import unittest

from safety_controls import (
    ScopeError,
    ensure_operation_allowed,
    load_scope_file,
    normalize_mac,
)


class SafetyControlsTests(unittest.TestCase):
    def test_normalize_mac_accepts_valid_address(self):
        self.assertEqual(normalize_mac("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF")

    def test_normalize_mac_rejects_invalid_address(self):
        with self.assertRaises(ValueError):
            normalize_mac("not-a-mac")

    def test_intrusive_command_requires_scope_or_confirmation(self):
        with self.assertRaises(ScopeError):
            ensure_operation_allowed(
                "dos",
                "AA:BB:CC:DD:EE:FF",
                scope=None,
                confirmed_authorized_scope=False,
                dry_run=False,
            )

    def test_dry_run_allows_intrusive_planning(self):
        ensure_operation_allowed(
            "dos",
            "AA:BB:CC:DD:EE:FF",
            scope=None,
            confirmed_authorized_scope=False,
            dry_run=True,
        )

    def test_scope_limits_targets_and_commands(self):
        with tempfile.TemporaryDirectory() as tempdir:
            scope_path = os.path.join(tempdir, "scope.json")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "authorization_id": "lab-001",
                        "authorized_macs": ["AA:BB:CC:DD:EE:FF"],
                        "allowed_commands": ["info", "dos"],
                    },
                    fh,
                )

            scope = load_scope_file(scope_path)
            ensure_operation_allowed(
                "dos",
                "AA:BB:CC:DD:EE:FF",
                scope=scope,
                confirmed_authorized_scope=False,
                dry_run=False,
            )
            with self.assertRaises(ScopeError):
                ensure_operation_allowed(
                    "send-file",
                    "AA:BB:CC:DD:EE:FF",
                    scope=scope,
                    confirmed_authorized_scope=False,
                    dry_run=False,
                )
            with self.assertRaises(ScopeError):
                ensure_operation_allowed(
                    "dos",
                    "11:22:33:44:55:66",
                    scope=scope,
                    confirmed_authorized_scope=False,
                    dry_run=False,
                )


if __name__ == "__main__":
    unittest.main()
