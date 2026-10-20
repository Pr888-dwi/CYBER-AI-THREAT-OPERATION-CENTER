import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from app import analyze_phishing, detect_intrusion, explain_threat, scan_malware


class CyberAIMVPTestCase(unittest.TestCase):
    def test_intrusion_detection(self):
        result = detect_intrusion([
            {"dst_port": 22, "bytes": 1200, "duration": 0.8},
            {"dst_port": 445, "bytes": 8500, "duration": 3.2},
            {"dst_port": 3389, "bytes": 30000, "duration": 1.5},
        ])
        self.assertEqual(result["risk"], "high")
        self.assertGreaterEqual(result["anomaly_score"], 4)

    def test_phishing_detection(self):
        result = analyze_phishing("Urgent! Click here to verify your password now")
        self.assertEqual(result["classification"], "phishing")

    def test_malware_scanning(self):
        result = scan_malware("payload.exe", 7000000)
        self.assertEqual(result["risk"], "high")

    def test_explanation(self):
        result = detect_intrusion([{"dst_port": 22, "bytes": 30000, "duration": 2.0}])
        answer = explain_threat(result, "Why was this flagged?")
        self.assertIn("flagged", answer.lower())


if __name__ == "__main__":
    unittest.main()
