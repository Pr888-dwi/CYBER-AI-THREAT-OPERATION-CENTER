import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from app import analyze_phishing, detect_intrusion, scan_malware
from database import ThreatDatabase
from ml_model import SimpleThreatModel


class AdvancedFeatureTests(unittest.TestCase):
    def test_real_model_prediction(self):
        model = SimpleThreatModel()
        result = model.predict([0.8, 0.7, 1.0, 1.0])
        self.assertIn("label", result)
        self.assertIn("score", result)

    def test_database_persists_alerts(self):
        os.makedirs("/tmp", exist_ok=True)
        db = ThreatDatabase(db_path="/tmp/cyberai-test.db")
        db.save_alert("high", "phishing", "test explanation")
        alerts = db.list_alerts()
        self.assertGreaterEqual(len(alerts), 1)

    def test_phishing_and_malware_modules(self):
        phishing = analyze_phishing("Urgent! Click here to verify your password")
        malware = scan_malware("evil.exe", 10_000_000)
        self.assertEqual(phishing["classification"], "phishing")
        self.assertEqual(malware["risk"], "high")


if __name__ == "__main__":
    unittest.main()
