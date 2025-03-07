import unittest
import os
import tempfile
from src.analyzer.code_analyzer import CodeAnalyzer
from src.analyzer.vulnerability_detector import VulnerabilityDetector

class TestCodeAnalyzer(unittest.TestCase):
    
    def setUp(self):
        self.code_analyzer = CodeAnalyzer()
        self.vuln_detector = VulnerabilityDetector()
        
        # Create temporary test files
        self.temp_dir = tempfile.mkdtemp()
        
        # Sample Python file with vulnerabilities
        self.python_file = os.path.join(self.temp_dir, "sample.py")
        with open(self.python_file, "w") as f:
            f.write("""
import os
import subprocess
import pickle

def execute_command(user_input):
    # Command injection vulnerability
    os.system("echo " + user_input)
    
def query_db(user_id):
    # SQL injection vulnerability
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    
def load_data(data):
    # Insecure deserialization
    return pickle.loads(data)
    
password = "hardcoded_secret123"  # Hardcoded secret
""")
    
    def tearDown(self):
        # Clean up temp files
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_find_files(self):
        files = self.code_analyzer.find_files(self.temp_dir)
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].endswith("sample.py"))
    
    def test_is_supported_file(self):
        self.assertTrue(self.code_analyzer.is_supported_file(self.python_file))
        self.assertFalse(self.code_analyzer.is_supported_file("nonexistent.xyz"))
    
    def test_vulnerability_detection(self):
        vulnerabilities = self.vuln_detector.scan_file(self.python_file)
        
        # Check that we found multiple vulnerabilities
        self.assertGreater(len(vulnerabilities), 2)
        
        # Check for specific vulnerability types
        vuln_types = [v["type"] for v in vulnerabilities]
        self.assertTrue(any("command_injection" in t.lower() for t in vuln_types))
        self.assertTrue(any("hardcoded_secret" in t.lower() for t in vuln_types))

if __name__ == "__main__":
    unittest.main()