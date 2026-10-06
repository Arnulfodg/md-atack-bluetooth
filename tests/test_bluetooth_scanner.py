import unittest

from bluetooth_scanner import BluetoothScanner


class BluetoothScannerTests(unittest.TestCase):
    def test_parse_bluetoothctl_scan_extracts_devices_and_rssi(self):
        output = """
        [NEW] Device AA:BB:CC:DD:EE:FF Pixel 8
        [CHG] Device AA:BB:CC:DD:EE:FF RSSI: -54
        [NEW] Device 11:22:33:44:55:66 Galaxy
        """

        rows = BluetoothScanner()._parse_bluetoothctl_scan(output)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(rows[0]["name"], "Pixel 8")
        self.assertEqual(rows[0]["rssi"], "-54")
        self.assertEqual(rows[1]["name"], "Galaxy")


if __name__ == "__main__":
    unittest.main()
