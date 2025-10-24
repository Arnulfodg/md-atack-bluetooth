import json
import os
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

# Stub bluetooth and PyOBEX modules so tests can run without the real dependencies
if "bluetooth" not in sys.modules:
    bluetooth_stub = types.ModuleType("bluetooth")
    bluetooth_stub.find_service = lambda *args, **kwargs: []
    sys.modules["bluetooth"] = bluetooth_stub

if "PyOBEX" not in sys.modules:
    pyobex_pkg = types.ModuleType("PyOBEX")
    sys.modules["PyOBEX"] = pyobex_pkg
    pyobex_client = types.ModuleType("PyOBEX.client")
    pyobex_client.Client = object
    sys.modules["PyOBEX.client"] = pyobex_client
    pyobex_headers = types.ModuleType("PyOBEX.headers")
    pyobex_headers.Target = object
    sys.modules["PyOBEX.headers"] = pyobex_headers

import blacklist_manager


class BlacklistManagerTests(unittest.TestCase):
    def setUp(self):
        self.scanner_patcher = patch("blacklist_manager.BluetoothScanner")
        self.mock_scanner_cls = self.scanner_patcher.start()
        self.addCleanup(self.scanner_patcher.stop)
        self.mock_scanner = self.mock_scanner_cls.return_value

        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.blacklist_path = os.path.join(self.tempdir.name, "blacklist.json")

        with open(self.blacklist_path, "w", encoding="utf-8") as fh:
            json.dump({"targets": ["AA:BB:CC:DD:EE:FF", {"mac": "11:22:33:44:55:66", "active": False}]}, fh)

        self.manager = blacklist_manager.BlacklistManager(
            adapter="hci0",
            blacklist_path=self.blacklist_path,
            watch_interval=1,
        )

    def test_matching_targets_only_returns_active_entries(self):
        self.mock_scanner.scan.return_value = {0: "AA:BB:CC:DD:EE:FF", 1: "11:22:33:44:55:66"}
        devices = self.manager._perform_scan()
        matches = self.manager._matching_targets(devices)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["mac"], "AA:BB:CC:DD:EE:FF")

    def test_toggle_mac_changes_active_state(self):
        self.manager.toggle_mac(0)
        self.assertFalse(self.manager.blacklist[0]["active"])
        self.mock_scanner.scan.return_value = {0: "AA:BB:CC:DD:EE:FF"}
        devices = self.manager._perform_scan()
        matches = self.manager._matching_targets(devices)
        self.assertEqual(matches, [])

    def test_launch_attack_spawns_thread_once(self):
        with patch("blacklist_manager.BluetoothAttacker.dos_attack", side_effect=lambda *args, **kwargs: time.sleep(0.05)) as mock_attack:
            self.manager._launch_attack("AA:BB:CC:DD:EE:FF")
            self.manager._launch_attack("AA:BB:CC:DD:EE:FF")
            time.sleep(0.1)
            with self.manager._lock:
                active_threads = len(self.manager._attack_threads)
            self.assertLessEqual(active_threads, 1)
            self.assertGreaterEqual(mock_attack.call_count, 1)


if __name__ == "__main__":
    unittest.main()
