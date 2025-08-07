#!/usr/bin/env python3
"""
Forensic Analysis Tool - Test Suite
Validates core functionality without GUI dependencies
"""

import sys
import os
import tempfile
import json
import csv
from pathlib import Path

# Add the current directory to path to import the forensic tool modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_file_recovery():
    """Test file recovery functionality"""
    print("🔍 Testing File Recovery Engine...")

    try:
        # Import without GUI dependencies
        from forensic_analysis_tool import FileRecoveryEngine

        recovery = FileRecoveryEngine()

        # Test recycle bin scan
        print("   - Testing Recycle Bin scan...")
        recycle_files = recovery.scan_recycle_bin()
        print(f"   - Found {len(recycle_files)} files in recycle bin")

        # Test deleted file scan (safe directories only)
        print("   - Testing deleted file scan...")
        if os.name == 'nt':
            deleted_files = recovery.scan_deleted_files("C:\\Windows\\Temp")
        else:
            deleted_files = recovery.scan_deleted_files("/tmp")
        print(f"   - Found {len(deleted_files)} deleted files")

        print("✅ File Recovery Engine: PASSED")
        return True

    except Exception as e:
        print(f"❌ File Recovery Engine: FAILED - {e}")
        return False

def test_log_analyzer():
    """Test log analysis functionality"""
    print("🔍 Testing Log Analyzer...")

    try:
        from forensic_analysis_tool import LogAnalyzer

        analyzer = LogAnalyzer()

        # Test Windows logs (will gracefully handle non-Windows systems)
        print("   - Testing Windows Event Log analysis...")
        event_logs = analyzer.analyze_windows_logs()
        print(f"   - Processed {len(event_logs)} event log entries")

        # Test browser history
        print("   - Testing browser history extraction...")
        browser_history = analyzer.analyze_browser_history()
        print(f"   - Found {len(browser_history)} browser history entries")

        print("✅ Log Analyzer: PASSED")
        return True

    except Exception as e:
        print(f"❌ Log Analyzer: FAILED - {e}")
        return False

def test_timeline_creator():
    """Test timeline creation functionality"""
    print("🔍 Testing Timeline Creator...")

    try:
        from forensic_analysis_tool import TimelineCreator
        import datetime

        timeline = TimelineCreator()

        # Create sample data for testing
        sample_files = [
            {
                'name': 'test.txt',
                'path': '/tmp/test.txt',
                'modified': datetime.datetime.now(),
                'accessed': datetime.datetime.now()
            }
        ]

        sample_logs = [
            {
                'log_type': 'System',
                'event_id': '1001',
                'source': 'Test',
                'timestamp': datetime.datetime.now().strftime('%m/%d/%Y %I:%M:%S %p'),
                'message': 'Test log entry'
            }
        ]

        sample_browser = [
            {
                'browser': 'Chrome',
                'title': 'Test Page',
                'url': 'https://test.com',
                'timestamp': datetime.datetime.now()
            }
        ]

        # Test timeline creation
        print("   - Creating timeline from sample data...")
        timeline_data = timeline.create_timeline(sample_files, sample_logs, sample_browser)
        print(f"   - Generated timeline with {len(timeline_data)} events")

        print("✅ Timeline Creator: PASSED")
        return True

    except Exception as e:
        print(f"❌ Timeline Creator: FAILED - {e}")
        return False

def test_evidence_collector():
    """Test evidence collection functionality"""
    print("🔍 Testing Evidence Collector...")

    try:
        from forensic_analysis_tool import EvidenceCollector

        collector = EvidenceCollector()

        # Create a temporary test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_file:
            tmp_file.write("This is a test evidence file.")
            test_file_path = tmp_file.name

        # Test evidence addition
        print("   - Adding test evidence file...")
        evidence_item = collector.add_evidence(test_file_path, "Test evidence file", "TEST001")
        print(f"   - Added evidence item with ID: {evidence_item['id']}")

        # Test evidence export
        with tempfile.TemporaryDirectory() as tmp_dir:
            print("   - Testing ZIP export...")
            zip_path = collector.export_evidence(tmp_dir, 'zip')
            print(f"   - Created ZIP archive: {zip_path}")

            print("   - Testing folder export...")
            folder_path = collector.export_evidence(tmp_dir, 'folder')
            print(f"   - Created evidence folder: {folder_path}")

        # Cleanup
        os.unlink(test_file_path)

        print("✅ Evidence Collector: PASSED")
        return True

    except Exception as e:
        print(f"❌ Evidence Collector: FAILED - {e}")
        return False

def test_report_generator():
    """Test report generation functionality"""
    print("🔍 Testing Report Generator...")

    try:
        from forensic_analysis_tool import ReportGenerator
        import datetime

        generator = ReportGenerator()

        # Sample data for reporting
        sample_data = [
            {
                'name': 'test.txt',
                'path': '/tmp/test.txt',
                'size': 1024,
                'modified': datetime.datetime.now(),
                'source': 'test',
                'hash': 'abc123'
            }
        ]

        with tempfile.TemporaryDirectory() as tmp_dir:
            # Test CSV report generation
            print("   - Testing CSV report generation...")
            csv_path = generator.generate_csv_report(sample_data, tmp_dir, 'test')
            print(f"   - Generated CSV report: {csv_path}")

            # Verify CSV content
            with open(csv_path, 'r') as csv_file:
                reader = csv.DictReader(csv_file)
                rows = list(reader)
                print(f"   - CSV contains {len(rows)} data rows")

            # Test HTML report generation
            print("   - Testing HTML report generation...")
            html_path = generator.generate_html_report(sample_data, [], [], [], tmp_dir)
            print(f"   - Generated HTML report: {html_path}")

            # Verify HTML content
            with open(html_path, 'r', encoding='utf-8') as html_file:
                html_content = html_file.read()
                print(f"   - HTML report size: {len(html_content)} characters")

        print("✅ Report Generator: PASSED")
        return True

    except Exception as e:
        print(f"❌ Report Generator: FAILED - {e}")
        return False

def test_system_compatibility():
    """Test system compatibility and requirements"""
    print("🔍 Testing System Compatibility...")

    try:
        # Check Python version
        python_version = sys.version_info
        print(f"   - Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")

        if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 6):
            print("   ⚠️  Warning: Python 3.6+ recommended")

        # Check required modules
        required_modules = ['os', 'sys', 'json', 'csv', 'sqlite3', 'datetime', 'subprocess', 
                          'shutil', 'zipfile', 'hashlib', 'xml.etree.ElementTree', 'pathlib',
                          'collections', 'threading', 'time']

        missing_modules = []
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)

        if missing_modules:
            print(f"   ❌ Missing required modules: {missing_modules}")
            return False
        else:
            print("   ✅ All required standard library modules available")

        # Check optional modules
        optional_modules = {
            'PyQt5': 'GUI interface',
            'send2trash': 'Recycle bin operations',
            'python-evtx': 'Windows Event Log parsing',
            'browser-history': 'Browser history extraction'
        }

        for module, description in optional_modules.items():
            try:
                if module == 'python-evtx':
                    import evtx.Evtx
                elif module == 'browser-history':
                    import browser_history
                else:
                    __import__(module.replace('-', '_'))
                print(f"   ✅ {module} available ({description})")
            except ImportError:
                print(f"   ⚠️  {module} not available ({description})")

        # Check platform
        platform = sys.platform
        print(f"   - Platform: {platform}")

        if platform.startswith('win'):
            print("   ✅ Windows platform detected - Full functionality available")
        else:
            print("   ⚠️  Non-Windows platform - Some features may be limited")

        print("✅ System Compatibility: PASSED")
        return True

    except Exception as e:
        print(f"❌ System Compatibility: FAILED - {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 Forensic Analysis Tool - Test Suite")
    print("=" * 50)

    tests = [
        ("System Compatibility", test_system_compatibility),
        ("File Recovery Engine", test_file_recovery),
        ("Log Analyzer", test_log_analyzer),
        ("Timeline Creator", test_timeline_creator),
        ("Evidence Collector", test_evidence_collector),
        ("Report Generator", test_report_generator)
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        print()
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ {test_name}: CRITICAL FAILURE - {e}")
            failed += 1

    print()
    print("=" * 50)
    print("🏁 Test Summary")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"📊 Success Rate: {(passed / (passed + failed)) * 100:.1f}%")

    if failed == 0:
        print("🎉 All tests passed! The forensic tool is ready for production use.")
        return 0
    else:
        print("⚠️  Some tests failed. Please review the issues above.")
        return 1

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
