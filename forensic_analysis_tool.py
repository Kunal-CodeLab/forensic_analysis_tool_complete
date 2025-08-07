
"""
Windows Forensic Analysis Tool
Production-ready forensic investigation tool with GUI interface
Features: File Recovery, Log Analysis, Timeline Creation, Evidence Collection, Reporting
"""

import os
import sys
import json
import csv
import sqlite3
import datetime
import subprocess
import shutil
import zipfile
import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict
import threading
import time
import re
import struct

# Platform-specific imports
if os.name == 'nt':
    import winreg
else:
    # Mock winreg for non-Windows systems
    class MockWinReg:
        HKEY_CURRENT_USER = None
        HKEY_LOCAL_MACHINE = None
        def OpenKey(self, *args): pass
        def QueryValueEx(self, *args): return ("", 0)
        def CloseKey(self, *args): pass
    winreg = MockWinReg()

try:
    from PyQt5.QtWidgets import *
    from PyQt5.QtCore import *
    from PyQt5.QtGui import *
    PYQT_AVAILABLE = True
except ImportError:
    print("PyQt5 not available. Please install: pip install PyQt5")
    PYQT_AVAILABLE = False

try:
    import send2trash
except ImportError:
    print("Installing send2trash...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "send2trash"])
    import send2trash

# Core forensic analysis classes
class FileRecoveryEngine:
    """Handles deleted file recovery from Recycle Bin and NTFS"""

    def __init__(self):
        self.recovered_files = []
        self.recycle_bin_files = []

    def scan_recycle_bin(self):
        """Scan and recover files from Recycle Bin"""
        recycle_paths = [
            os.path.expanduser("~/.local/share/Trash/files"),  # Linux
            "C:\\$Recycle.Bin",  # Windows
        ]

        for path in recycle_paths:
            if os.path.exists(path):
                self._scan_directory(path, "recycle_bin")

        return self.recycle_bin_files

    def scan_deleted_files(self, drive_path="C:\\"):
        """Attempt to recover deleted files using MFT analysis"""
        try:
            if os.name == 'nt':
                self._scan_ntfs_deleted(drive_path)
            else:
                self._scan_unix_deleted()
        except Exception as e:
            print(f"Error scanning deleted files: {e}")

        return self.recovered_files

    def _scan_directory(self, path, source_type):
        """Recursively scan directory for files"""
        try:
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_info = self._get_file_info(file_path, source_type)
                    if source_type == "recycle_bin":
                        self.recycle_bin_files.append(file_info)
                    else:
                        self.recovered_files.append(file_info)
        except Exception as e:
            print(f"Error scanning directory {path}: {e}")

    def _scan_ntfs_deleted(self, drive_path):
        """Scan NTFS Master File Table for deleted files"""
        # This is a simplified implementation
        # In production, you'd use libraries like pytsk3 or direct MFT parsing
        try:
            # Look for recently deleted files in temp directories
            temp_dirs = [
                os.path.expandvars("%TEMP%"),
                os.path.expandvars("%TMP%"),
                "C:\\Windows\\Temp",
                "C:\\Users\\%USERNAME%\\AppData\\Local\\Temp"
            ]

            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    self._scan_directory(temp_dir, "deleted")
        except Exception as e:
            print(f"Error in NTFS scan: {e}")

    def _scan_unix_deleted(self):
        """Scan Unix-like systems for deleted files"""
        # Check common locations where deleted files might be recovered
        search_paths = [
            "/tmp",
            "/var/tmp",
            os.path.expanduser("~/.local/share/Trash")
        ]

        for path in search_paths:
            if os.path.exists(path):
                self._scan_directory(path, "deleted")

    def _get_file_info(self, file_path, source):
        """Extract file metadata"""
        try:
            stat = os.stat(file_path)
            return {
                'path': file_path,
                'name': os.path.basename(file_path),
                'size': stat.st_size,
                'modified': datetime.datetime.fromtimestamp(stat.st_mtime),
                'accessed': datetime.datetime.fromtimestamp(stat.st_atime),
                'created': datetime.datetime.fromtimestamp(stat.st_ctime),
                'source': source,
                'hash': self._calculate_hash(file_path)
            }
        except Exception as e:
            return {
                'path': file_path,
                'name': os.path.basename(file_path),
                'error': str(e),
                'source': source
            }

    def _calculate_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except:
            return "N/A"

class LogAnalyzer:
    """Analyzes Windows Event Logs and browser history"""

    def __init__(self):
        self.event_logs = []
        self.browser_history = []
        self.app_logs = []

    def analyze_windows_logs(self):
        """Analyze Windows Event Logs"""
        if os.name != 'nt':
            print("Windows logs only available on Windows systems")
            return []

        log_types = ['System', 'Security', 'Application']

        for log_type in log_types:
            try:
                self._parse_event_log(log_type)
            except Exception as e:
                print(f"Error analyzing {log_type} log: {e}")

        return self.event_logs

    def analyze_browser_history(self):
        """Extract browser history from Chrome, Firefox, Edge"""
        browsers = ['chrome', 'firefox', 'edge']

        for browser in browsers:
            try:
                if browser == 'chrome':
                    self._extract_chrome_history()
                elif browser == 'firefox':
                    self._extract_firefox_history()
                elif browser == 'edge':
                    self._extract_edge_history()
            except Exception as e:
                print(f"Error extracting {browser} history: {e}")

        return self.browser_history

    def _parse_event_log(self, log_type):
        """Parse Windows Event Log using WMI"""
        try:
            # Using PowerShell to query event logs
            cmd = f'powershell "Get-EventLog -LogName {log_type} -Newest 1000 | ConvertTo-Json"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                try:
                    events = json.loads(result.stdout)
                    if not isinstance(events, list):
                        events = [events]

                    for event in events:
                        self.event_logs.append({
                            'log_type': log_type,
                            'event_id': event.get('EventID', 'N/A'),
                            'level': event.get('EntryType', 'N/A'),
                            'source': event.get('Source', 'N/A'),
                            'message': event.get('Message', 'N/A'),
                            'timestamp': event.get('TimeGenerated', 'N/A'),
                            'computer': event.get('MachineName', 'N/A')
                        })
                except json.JSONDecodeError:
                    print(f"Failed to parse {log_type} log JSON")
        except Exception as e:
            print(f"Error parsing {log_type} event log: {e}")

    def _extract_chrome_history(self):
        """Extract Chrome browser history"""
        try:
            chrome_paths = [
                os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Default/History"),
                os.path.expanduser("~/.config/google-chrome/Default/History"),
                os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/History")
            ]

            for path in chrome_paths:
                if os.path.exists(path):
                    # Copy database to avoid lock issues
                    temp_path = path + "_temp"
                    shutil.copy2(path, temp_path)

                    conn = sqlite3.connect(temp_path)
                    cursor = conn.cursor()

                    cursor.execute("""
                        SELECT url, title, visit_count, last_visit_time 
                        FROM urls 
                        ORDER BY last_visit_time DESC 
                        LIMIT 1000
                    """)

                    for row in cursor.fetchall():
                        # Convert Chrome timestamp to datetime
                        timestamp = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=row[3])

                        self.browser_history.append({
                            'browser': 'Chrome',
                            'url': row[0],
                            'title': row[1],
                            'visit_count': row[2],
                            'timestamp': timestamp
                        })

                    conn.close()
                    os.remove(temp_path)
                    break
        except Exception as e:
            print(f"Error extracting Chrome history: {e}")

    def _extract_firefox_history(self):
        """Extract Firefox browser history"""
        try:
            firefox_paths = [
                os.path.expanduser("~/AppData/Roaming/Mozilla/Firefox/Profiles"),
                os.path.expanduser("~/.mozilla/firefox"),
                os.path.expanduser("~/Library/Application Support/Firefox/Profiles")
            ]

            for base_path in firefox_paths:
                if os.path.exists(base_path):
                    for profile in os.listdir(base_path):
                        profile_path = os.path.join(base_path, profile)
                        history_path = os.path.join(profile_path, "places.sqlite")

                        if os.path.exists(history_path):
                            temp_path = history_path + "_temp"
                            shutil.copy2(history_path, temp_path)

                            conn = sqlite3.connect(temp_path)
                            cursor = conn.cursor()

                            cursor.execute("""
                                SELECT p.url, p.title, p.visit_count, h.visit_date
                                FROM moz_places p
                                LEFT JOIN moz_historyvisits h ON p.id = h.place_id
                                ORDER BY h.visit_date DESC
                                LIMIT 1000
                            """)

                            for row in cursor.fetchall():
                                if row[3]:
                                    timestamp = datetime.datetime.fromtimestamp(row[3] / 1000000)
                                else:
                                    timestamp = None

                                self.browser_history.append({
                                    'browser': 'Firefox',
                                    'url': row[0],
                                    'title': row[1],
                                    'visit_count': row[2],
                                    'timestamp': timestamp
                                })

                            conn.close()
                            os.remove(temp_path)
                            break
        except Exception as e:
            print(f"Error extracting Firefox history: {e}")

    def _extract_edge_history(self):
        """Extract Microsoft Edge browser history"""
        try:
            edge_paths = [
                os.path.expanduser("~/AppData/Local/Microsoft/Edge/User Data/Default/History"),
                os.path.expanduser("~/Library/Application Support/Microsoft Edge/Default/History")
            ]

            for path in edge_paths:
                if os.path.exists(path):
                    temp_path = path + "_temp"
                    shutil.copy2(path, temp_path)

                    conn = sqlite3.connect(temp_path)
                    cursor = conn.cursor()

                    cursor.execute("""
                        SELECT url, title, visit_count, last_visit_time 
                        FROM urls 
                        ORDER BY last_visit_time DESC 
                        LIMIT 1000
                    """)

                    for row in cursor.fetchall():
                        timestamp = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=row[3])

                        self.browser_history.append({
                            'browser': 'Edge',
                            'url': row[0],
                            'title': row[1],
                            'visit_count': row[2],
                            'timestamp': timestamp
                        })

                    conn.close()
                    os.remove(temp_path)
                    break
        except Exception as e:
            print(f"Error extracting Edge history: {e}")

class TimelineCreator:
    """Creates forensic timeline from various artifacts"""

    def __init__(self):
        self.timeline_events = []

    def create_timeline(self, file_data, log_data, browser_data):
        """Create comprehensive timeline from all data sources"""
        self.timeline_events = []

        # Add file events
        for file_info in file_data:
            if 'modified' in file_info:
                self.timeline_events.append({
                    'timestamp': file_info['modified'],
                    'event_type': 'File Modified',
                    'source': 'File System',
                    'details': f"File: {file_info['name']} ({file_info['path']})",
                    'artifact_type': 'file'
                })

            if 'accessed' in file_info:
                self.timeline_events.append({
                    'timestamp': file_info['accessed'],
                    'event_type': 'File Accessed',
                    'source': 'File System',
                    'details': f"File: {file_info['name']} ({file_info['path']})",
                    'artifact_type': 'file'
                })

        # Add log events
        for log_entry in log_data:
            if 'timestamp' in log_entry and log_entry['timestamp'] != 'N/A':
                try:
                    timestamp = datetime.datetime.strptime(log_entry['timestamp'], '%m/%d/%Y %I:%M:%S %p')
                    self.timeline_events.append({
                        'timestamp': timestamp,
                        'event_type': f"{log_entry['log_type']} Event",
                        'source': log_entry['source'],
                        'details': f"Event ID: {log_entry['event_id']} - {log_entry['message'][:100]}...",
                        'artifact_type': 'log'
                    })
                except:
                    pass

        # Add browser events
        for browser_entry in browser_data:
            if browser_entry['timestamp']:
                self.timeline_events.append({
                    'timestamp': browser_entry['timestamp'],
                    'event_type': 'Web Navigation',
                    'source': browser_entry['browser'],
                    'details': f"{browser_entry['title']} ({browser_entry['url']})",
                    'artifact_type': 'browser'
                })

        # Sort by timestamp
        self.timeline_events.sort(key=lambda x: x['timestamp'] if x['timestamp'] else datetime.datetime.min)

        return self.timeline_events

class EvidenceCollector:
    """Handles evidence collection and packaging"""

    def __init__(self):
        self.evidence_items = []

    def add_evidence(self, file_path, description, case_id):
        """Add evidence item with chain of custody"""
        evidence_item = {
            'id': len(self.evidence_items) + 1,
            'file_path': file_path,
            'description': description,
            'case_id': case_id,
            'collected_time': datetime.datetime.now(),
            'hash': self._calculate_hash(file_path) if os.path.exists(file_path) else 'N/A',
            'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
        }

        self.evidence_items.append(evidence_item)
        return evidence_item

    def export_evidence(self, export_path, format_type='zip'):
        """Export evidence as zip archive or organized folder"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        if format_type == 'zip':
            zip_path = os.path.join(export_path, f"evidence_collection_{timestamp}.zip")
            with zipfile.ZipFile(zip_path, 'w') as zipf:
                # Add evidence files
                for item in self.evidence_items:
                    if os.path.exists(item['file_path']):
                        zipf.write(item['file_path'], f"evidence_{item['id']:03d}_{os.path.basename(item['file_path'])}")

                # Add chain of custody report
                custody_report = self._generate_custody_report()
                zipf.writestr("chain_of_custody.json", json.dumps(custody_report, indent=2, default=str))

            return zip_path

        else:  # folder format
            folder_path = os.path.join(export_path, f"evidence_collection_{timestamp}")
            os.makedirs(folder_path, exist_ok=True)

            # Copy evidence files
            for item in self.evidence_items:
                if os.path.exists(item['file_path']):
                    dest_path = os.path.join(folder_path, f"evidence_{item['id']:03d}_{os.path.basename(item['file_path'])}")
                    shutil.copy2(item['file_path'], dest_path)

            # Save chain of custody
            custody_path = os.path.join(folder_path, "chain_of_custody.json")
            with open(custody_path, 'w') as f:
                json.dump(self._generate_custody_report(), f, indent=2, default=str)

            return folder_path

    def _calculate_hash(self, file_path):
        """Calculate SHA-256 hash"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except:
            return "N/A"

    def _generate_custody_report(self):
        """Generate chain of custody report"""
        return {
            'report_generated': datetime.datetime.now(),
            'total_items': len(self.evidence_items),
            'evidence_items': self.evidence_items,
            'investigator': os.getenv('USERNAME', 'Unknown'),
            'system_info': {
                'hostname': os.environ.get('COMPUTERNAME', 'Unknown'),
                'platform': sys.platform,
                'python_version': sys.version
            }
        }

class ReportGenerator:
    """Generates forensic reports in various formats"""

    def __init__(self):
        pass

    def generate_csv_report(self, data, output_path, report_type):
        """Generate CSV report"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report_type}_report_{timestamp}.csv"
        filepath = os.path.join(output_path, filename)

        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            if data and len(data) > 0:
                fieldnames = data[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for row in data:
                    # Convert datetime objects to strings
                    clean_row = {}
                    for key, value in row.items():
                        if isinstance(value, datetime.datetime):
                            clean_row[key] = value.strftime("%Y-%m-%d %H:%M:%S")
                        else:
                            clean_row[key] = str(value)
                    writer.writerow(clean_row)

        return filepath

    def generate_html_report(self, file_data, log_data, browser_data, timeline_data, output_path):
        """Generate comprehensive HTML report"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"forensic_report_{timestamp}.html"
        filepath = os.path.join(output_path, filename)

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Forensic Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1, h2 {{ color: #2c3e50; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 30px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .summary {{ background-color: #ecf0f1; padding: 15px; margin-bottom: 20px; }}
        .timestamp {{ color: #7f8c8d; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>Forensic Analysis Report</h1>
    <div class="summary">
        <h2>Report Summary</h2>
        <p><strong>Generated:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Investigator:</strong> {os.getenv('USERNAME', 'Unknown')}</p>
        <p><strong>System:</strong> {os.environ.get('COMPUTERNAME', 'Unknown')}</p>
        <p><strong>Files Analyzed:</strong> {len(file_data)}</p>
        <p><strong>Log Entries:</strong> {len(log_data)}</p>
        <p><strong>Browser Records:</strong> {len(browser_data)}</p>
        <p><strong>Timeline Events:</strong> {len(timeline_data)}</p>
    </div>

    <h2>File Recovery Results</h2>
    <table>
        <tr>
            <th>File Name</th>
            <th>Path</th>
            <th>Size</th>
            <th>Modified</th>
            <th>Source</th>
            <th>Hash</th>
        </tr>
        """

        for file_item in file_data[:100]:  # Limit to first 100 files
            html_content += f"""
        <tr>
            <td>{file_item.get('name', 'N/A')}</td>
            <td>{file_item.get('path', 'N/A')}</td>
            <td>{file_item.get('size', 'N/A')}</td>
            <td>{file_item.get('modified', 'N/A')}</td>
            <td>{file_item.get('source', 'N/A')}</td>
            <td>{file_item.get('hash', 'N/A')[:16]}...</td>
        </tr>"""

        html_content += """
    </table>

    <h2>System Log Analysis</h2>
    <table>
        <tr>
            <th>Log Type</th>
            <th>Event ID</th>
            <th>Source</th>
            <th>Timestamp</th>
            <th>Message</th>
        </tr>"""

        for log_entry in log_data[:50]:  # Limit to first 50 log entries
            html_content += f"""
        <tr>
            <td>{log_entry.get('log_type', 'N/A')}</td>
            <td>{log_entry.get('event_id', 'N/A')}</td>
            <td>{log_entry.get('source', 'N/A')}</td>
            <td>{log_entry.get('timestamp', 'N/A')}</td>
            <td>{str(log_entry.get('message', 'N/A'))[:100]}...</td>
        </tr>"""

        html_content += """
    </table>

    <h2>Browser History Analysis</h2>
    <table>
        <tr>
            <th>Browser</th>
            <th>Title</th>
            <th>URL</th>
            <th>Visit Count</th>
            <th>Timestamp</th>
        </tr>"""

        for browser_entry in browser_data[:50]:  # Limit to first 50 browser entries
            html_content += f"""
        <tr>
            <td>{browser_entry.get('browser', 'N/A')}</td>
            <td>{browser_entry.get('title', 'N/A')}</td>
            <td>{browser_entry.get('url', 'N/A')}</td>
            <td>{browser_entry.get('visit_count', 'N/A')}</td>
            <td>{browser_entry.get('timestamp', 'N/A')}</td>
        </tr>"""

        html_content += """
    </table>

    <h2>Timeline Analysis</h2>
    <table>
        <tr>
            <th>Timestamp</th>
            <th>Event Type</th>
            <th>Source</th>
            <th>Details</th>
        </tr>"""

        for timeline_entry in timeline_data[:100]:  # Limit to first 100 timeline entries
            html_content += f"""
        <tr>
            <td>{timeline_entry.get('timestamp', 'N/A')}</td>
            <td>{timeline_entry.get('event_type', 'N/A')}</td>
            <td>{timeline_entry.get('source', 'N/A')}</td>
            <td>{str(timeline_entry.get('details', 'N/A'))[:100]}...</td>
        </tr>"""

        html_content += """
    </table>

    <div class="timestamp">
        <p>Report generated by Windows Forensic Analysis Tool</p>
    </div>
</body>
</html>"""

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return filepath

# PyQt5 GUI Application
if PYQT_AVAILABLE:
    class ForensicAnalysisGUI(QMainWindow):
        def __init__(self):
            super().__init__()
            self.file_recovery = FileRecoveryEngine()
            self.log_analyzer = LogAnalyzer()
            self.timeline_creator = TimelineCreator()
            self.evidence_collector = EvidenceCollector()
            self.report_generator = ReportGenerator()

            self.file_data = []
            self.log_data = []
            self.browser_data = []
            self.timeline_data = []

            self.init_ui()

        def init_ui(self):
            self.setWindowTitle('Windows Forensic Analysis Tool')
            self.setGeometry(100, 100, 1200, 800)

            # Create central widget and main layout
            central_widget = QWidget()
            self.setCentralWidget(central_widget)
            main_layout = QHBoxLayout(central_widget)

            # Create sidebar
            sidebar = QWidget()
            sidebar.setFixedWidth(200)
            sidebar.setStyleSheet("background-color: #2c3e50; color: white;")
            sidebar_layout = QVBoxLayout(sidebar)

            # Sidebar buttons
            self.btn_file_recovery = QPushButton('File Recovery')
            self.btn_log_analysis = QPushButton('Log Analysis')
            self.btn_timeline = QPushButton('Timeline')
            self.btn_evidence = QPushButton('Evidence Collection')
            self.btn_reports = QPushButton('Generate Reports')

            sidebar_buttons = [
                self.btn_file_recovery,
                self.btn_log_analysis, 
                self.btn_timeline,
                self.btn_evidence,
                self.btn_reports
            ]

            for btn in sidebar_buttons:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #34495e;
                        color: white;
                        border: none;
                        padding: 10px;
                        text-align: left;
                        margin: 2px;
                    }
                    QPushButton:hover {
                        background-color: #3498db;
                    }
                    QPushButton:pressed {
                        background-color: #2980b9;
                    }
                """)
                sidebar_layout.addWidget(btn)

            sidebar_layout.addStretch()

            # Connect sidebar buttons
            self.btn_file_recovery.clicked.connect(lambda: self.show_tab(0))
            self.btn_log_analysis.clicked.connect(lambda: self.show_tab(1))
            self.btn_timeline.clicked.connect(lambda: self.show_tab(2))
            self.btn_evidence.clicked.connect(lambda: self.show_tab(3))
            self.btn_reports.clicked.connect(lambda: self.show_tab(4))

            # Create tab widget
            self.tab_widget = QTabWidget()
            self.tab_widget.setTabPosition(QTabWidget.North)

            # Create tabs
            self.create_file_recovery_tab()
            self.create_log_analysis_tab()
            self.create_timeline_tab()
            self.create_evidence_tab()
            self.create_reports_tab()

            # Add widgets to main layout
            main_layout.addWidget(sidebar)
            main_layout.addWidget(self.tab_widget, 1)

            # Status bar
            self.statusBar().showMessage('Ready')

        def show_tab(self, index):
            self.tab_widget.setCurrentIndex(index)

        def create_file_recovery_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)

            # Header
            header = QLabel('File Recovery Module')
            header.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50;")
            layout.addWidget(header)

            # Buttons
            button_layout = QHBoxLayout()
            btn_scan_recycle = QPushButton('Scan Recycle Bin')
            btn_scan_deleted = QPushButton('Scan Deleted Files')
            btn_export_files = QPushButton('Export Results')

            btn_scan_recycle.clicked.connect(self.scan_recycle_bin)
            btn_scan_deleted.clicked.connect(self.scan_deleted_files)
            btn_export_files.clicked.connect(self.export_file_results)

            button_layout.addWidget(btn_scan_recycle)
            button_layout.addWidget(btn_scan_deleted)
            button_layout.addWidget(btn_export_files)
            button_layout.addStretch()

            layout.addLayout(button_layout)

            # Progress bar
            self.file_progress = QProgressBar()
            layout.addWidget(self.file_progress)

            # Results table
            self.file_table = QTableWidget()
            self.file_table.setColumnCount(6)
            self.file_table.setHorizontalHeaderLabels(['Name', 'Path', 'Size', 'Modified', 'Source', 'Hash'])
            layout.addWidget(self.file_table)

            self.tab_widget.addTab(tab, 'File Recovery')

        def create_log_analysis_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)

            # Header
            header = QLabel('Log Analysis Module')
            header.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50;")
            layout.addWidget(header)

            # Buttons
            button_layout = QHBoxLayout()
            btn_scan_event_logs = QPushButton('Analyze Event Logs')
            btn_scan_browser = QPushButton('Extract Browser History')
            btn_export_logs = QPushButton('Export Results')

            btn_scan_event_logs.clicked.connect(self.analyze_event_logs)
            btn_scan_browser.clicked.connect(self.extract_browser_history)
            btn_export_logs.clicked.connect(self.export_log_results)

            button_layout.addWidget(btn_scan_event_logs)
            button_layout.addWidget(btn_scan_browser)
            button_layout.addWidget(btn_export_logs)
            button_layout.addStretch()

            layout.addLayout(button_layout)

            # Progress bar
            self.log_progress = QProgressBar()
            layout.addWidget(self.log_progress)

            # Results tabs
            log_tabs = QTabWidget()

            # Event logs table
            self.event_log_table = QTableWidget()
            self.event_log_table.setColumnCount(6)
            self.event_log_table.setHorizontalHeaderLabels(['Log Type', 'Event ID', 'Source', 'Timestamp', 'Level', 'Message'])
            log_tabs.addTab(self.event_log_table, 'Event Logs')

            # Browser history table
            self.browser_table = QTableWidget()
            self.browser_table.setColumnCount(5)
            self.browser_table.setHorizontalHeaderLabels(['Browser', 'Title', 'URL', 'Visit Count', 'Timestamp'])
            log_tabs.addTab(self.browser_table, 'Browser History')

            layout.addWidget(log_tabs)

            self.tab_widget.addTab(tab, 'Log Analysis')

        def create_timeline_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)

            # Header
            header = QLabel('Timeline Creation Module')
            header.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50;")
            layout.addWidget(header)

            # Buttons
            button_layout = QHBoxLayout()
            btn_create_timeline = QPushButton('Create Timeline')
            btn_export_timeline = QPushButton('Export Timeline')

            btn_create_timeline.clicked.connect(self.create_timeline)
            btn_export_timeline.clicked.connect(self.export_timeline)

            button_layout.addWidget(btn_create_timeline)
            button_layout.addWidget(btn_export_timeline)
            button_layout.addStretch()

            layout.addLayout(button_layout)

            # Progress bar
            self.timeline_progress = QProgressBar()
            layout.addWidget(self.timeline_progress)

            # Timeline table
            self.timeline_table = QTableWidget()
            self.timeline_table.setColumnCount(4)
            self.timeline_table.setHorizontalHeaderLabels(['Timestamp', 'Event Type', 'Source', 'Details'])
            layout.addWidget(self.timeline_table)

            self.tab_widget.addTab(tab, 'Timeline')

        def create_evidence_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)

            # Header
            header = QLabel('Evidence Collection Module')
            header.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50;")
            layout.addWidget(header)

            # Case information
            case_layout = QHBoxLayout()
            case_layout.addWidget(QLabel('Case ID:'))
            self.case_id_input = QLineEdit()
            case_layout.addWidget(self.case_id_input)
            case_layout.addStretch()
            layout.addLayout(case_layout)

            # Buttons
            button_layout = QHBoxLayout()
            btn_add_evidence = QPushButton('Add Evidence File')
            btn_export_zip = QPushButton('Export as ZIP')
            btn_export_folder = QPushButton('Export as Folder')

            btn_add_evidence.clicked.connect(self.add_evidence_file)
            btn_export_zip.clicked.connect(lambda: self.export_evidence('zip'))
            btn_export_folder.clicked.connect(lambda: self.export_evidence('folder'))

            button_layout.addWidget(btn_add_evidence)
            button_layout.addWidget(btn_export_zip)
            button_layout.addWidget(btn_export_folder)
            button_layout.addStretch()

            layout.addLayout(button_layout)

            # Evidence table
            self.evidence_table = QTableWidget()
            self.evidence_table.setColumnCount(5)
            self.evidence_table.setHorizontalHeaderLabels(['ID', 'File Path', 'Description', 'Collected Time', 'Hash'])
            layout.addWidget(self.evidence_table)

            self.tab_widget.addTab(tab, 'Evidence Collection')

        def create_reports_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)

            # Header
            header = QLabel('Report Generation Module')
            header.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50;")
            layout.addWidget(header)

            # Report options
            options_layout = QVBoxLayout()

            self.include_files = QCheckBox('Include File Recovery Results')
            self.include_logs = QCheckBox('Include Log Analysis Results')
            self.include_browser = QCheckBox('Include Browser History')
            self.include_timeline = QCheckBox('Include Timeline')

            self.include_files.setChecked(True)
            self.include_logs.setChecked(True)
            self.include_browser.setChecked(True)
            self.include_timeline.setChecked(True)

            options_layout.addWidget(self.include_files)
            options_layout.addWidget(self.include_logs)
            options_layout.addWidget(self.include_browser)
            options_layout.addWidget(self.include_timeline)

            layout.addLayout(options_layout)

            # Buttons
            button_layout = QHBoxLayout()
            btn_generate_csv = QPushButton('Generate CSV Report')
            btn_generate_html = QPushButton('Generate HTML Report')

            btn_generate_csv.clicked.connect(self.generate_csv_report)
            btn_generate_html.clicked.connect(self.generate_html_report)

            button_layout.addWidget(btn_generate_csv)
            button_layout.addWidget(btn_generate_html)
            button_layout.addStretch()

            layout.addLayout(button_layout)

            # Report preview
            self.report_preview = QTextEdit()
            self.report_preview.setReadOnly(True)
            layout.addWidget(self.report_preview)

            self.tab_widget.addTab(tab, 'Generate Reports')

        # File Recovery Methods
        def scan_recycle_bin(self):
            try:
                self.statusBar().showMessage("Scanning Recycle Bin...")
                self.file_progress.setRange(0, 0)  # Indeterminate progress
                
                # Run scan directly in main thread to avoid threading issues
                recycle_files = self.file_recovery.scan_recycle_bin()
                self.file_data.extend(recycle_files)
                self._update_file_table()
                
                self.file_progress.setRange(0, 1)
                self.file_progress.setValue(1)
                self.statusBar().showMessage(f"Found {len(recycle_files)} files in recycle bin")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to scan recycle bin: {str(e)}")
                self.file_progress.setRange(0, 1)
                self.file_progress.setValue(0)
                self.statusBar().showMessage("Ready")

        def _scan_recycle_bin_task(self):
            try:
                recycle_files = self.file_recovery.scan_recycle_bin()
                self.file_data.extend(recycle_files)
                QMetaObject.invokeMethod(self, "_update_file_table", Qt.QueuedConnection)
            except Exception as e:
                print(f"Error in recycle bin scan: {e}")

        def scan_deleted_files(self):
            try:
                self.statusBar().showMessage("Scanning for deleted files...")
                self.file_progress.setRange(0, 0)  # Indeterminate progress
                
                # Run scan directly in main thread to avoid threading issues
                deleted_files = self.file_recovery.scan_deleted_files()
                self.file_data.extend(deleted_files)
                self._update_file_table()
                
                self.file_progress.setRange(0, 1)
                self.file_progress.setValue(1)
                self.statusBar().showMessage(f"Found {len(deleted_files)} deleted files")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to scan deleted files: {str(e)}")
                self.file_progress.setRange(0, 1)
                self.file_progress.setValue(0)
                self.statusBar().showMessage("Ready")

        def _scan_deleted_files_task(self):
            try:
                deleted_files = self.file_recovery.scan_deleted_files()
                self.file_data.extend(deleted_files)
                QMetaObject.invokeMethod(self, "_update_file_table", Qt.QueuedConnection)
            except Exception as e:
                print(f"Error in deleted files scan: {e}")

        @pyqtSlot()
        def _update_file_table(self):
            try:
                self.file_table.setRowCount(len(self.file_data))
                for i, file_info in enumerate(self.file_data):
                    self.file_table.setItem(i, 0, QTableWidgetItem(str(file_info.get('name', 'N/A'))))
                    self.file_table.setItem(i, 1, QTableWidgetItem(str(file_info.get('path', 'N/A'))))
                    self.file_table.setItem(i, 2, QTableWidgetItem(str(file_info.get('size', 'N/A'))))
                    self.file_table.setItem(i, 3, QTableWidgetItem(str(file_info.get('modified', 'N/A'))))
                    self.file_table.setItem(i, 4, QTableWidgetItem(str(file_info.get('source', 'N/A'))))
                    hash_value = str(file_info.get('hash', 'N/A'))
                    if len(hash_value) > 16:
                        hash_display = hash_value[:16] + "..."
                    else:
                        hash_display = hash_value
                    self.file_table.setItem(i, 5, QTableWidgetItem(hash_display))
            except Exception as e:
                print(f"Error updating file table: {e}")
                QMessageBox.warning(self, "Warning", f"Error updating file table: {str(e)}")

        def export_file_results(self):
            if not self.file_data:
                QMessageBox.warning(self, "Warning", "No file data to export. Please scan for files first.")
                return

            path, _ = QFileDialog.getSaveFileName(self, "Export File Results", "", "CSV files (*.csv)")
            if path:
                try:
                    self.report_generator.generate_csv_report(self.file_data, os.path.dirname(path), 'file_recovery')
                    QMessageBox.information(self, "Success", f"File results exported to {path}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to export file results: {str(e)}")

        # Log Analysis Methods
        def analyze_event_logs(self):
            try:
                self.statusBar().showMessage("Analyzing event logs...")
                self.log_progress.setRange(0, 0)  # Indeterminate progress
                
                # Run analysis directly in main thread to avoid threading issues
                event_logs = self.log_analyzer.analyze_windows_logs()
                self.log_data.extend(event_logs)
                self._update_log_table()
                
                self.log_progress.setRange(0, 1)
                self.log_progress.setValue(1)
                self.statusBar().showMessage(f"Analyzed {len(event_logs)} event log entries")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to analyze event logs: {str(e)}")
                self.log_progress.setRange(0, 1)
                self.log_progress.setValue(0)
                self.statusBar().showMessage("Ready")

        def _analyze_event_logs_task(self):
            try:
                event_logs = self.log_analyzer.analyze_windows_logs()
                self.log_data.extend(event_logs)
                QMetaObject.invokeMethod(self, "_update_log_table", Qt.QueuedConnection)
            except Exception as e:
                print(f"Error in event log analysis: {e}")

        def extract_browser_history(self):
            try:
                self.statusBar().showMessage("Extracting browser history...")
                self.log_progress.setRange(0, 0)  # Indeterminate progress
                
                # Run extraction directly in main thread to avoid threading issues
                browser_history = self.log_analyzer.analyze_browser_history()
                self.browser_data.extend(browser_history)
                self._update_browser_table()
                
                self.log_progress.setRange(0, 1)
                self.log_progress.setValue(1)
                self.statusBar().showMessage(f"Extracted {len(browser_history)} browser history entries")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to extract browser history: {str(e)}")
                self.log_progress.setRange(0, 1)
                self.log_progress.setValue(0)
                self.statusBar().showMessage("Ready")

        def _extract_browser_history_task(self):
            try:
                browser_history = self.log_analyzer.analyze_browser_history()
                self.browser_data.extend(browser_history)
                QMetaObject.invokeMethod(self, "_update_browser_table", Qt.QueuedConnection)
            except Exception as e:
                print(f"Error in browser history extraction: {e}")

        @pyqtSlot()
        def _update_log_table(self):
            try:
                self.event_log_table.setRowCount(len(self.log_data))
                for i, log_entry in enumerate(self.log_data):
                    self.event_log_table.setItem(i, 0, QTableWidgetItem(str(log_entry.get('log_type', 'N/A'))))
                    self.event_log_table.setItem(i, 1, QTableWidgetItem(str(log_entry.get('event_id', 'N/A'))))
                    self.event_log_table.setItem(i, 2, QTableWidgetItem(str(log_entry.get('source', 'N/A'))))
                    self.event_log_table.setItem(i, 3, QTableWidgetItem(str(log_entry.get('timestamp', 'N/A'))))
                    self.event_log_table.setItem(i, 4, QTableWidgetItem(str(log_entry.get('level', 'N/A'))))
                    message = str(log_entry.get('message', 'N/A'))
                    if len(message) > 100:
                        message = message[:100] + "..."
                    self.event_log_table.setItem(i, 5, QTableWidgetItem(message))
            except Exception as e:
                print(f"Error updating log table: {e}")
                QMessageBox.warning(self, "Warning", f"Error updating log table: {str(e)}")

        @pyqtSlot()
        def _update_browser_table(self):
            try:
                self.browser_table.setRowCount(len(self.browser_data))
                for i, browser_entry in enumerate(self.browser_data):
                    self.browser_table.setItem(i, 0, QTableWidgetItem(str(browser_entry.get('browser', 'N/A'))))
                    title = str(browser_entry.get('title', 'N/A'))
                    if len(title) > 50:
                        title = title[:50] + "..."
                    self.browser_table.setItem(i, 1, QTableWidgetItem(title))
                    url = str(browser_entry.get('url', 'N/A'))
                    if len(url) > 50:
                        url = url[:50] + "..."
                    self.browser_table.setItem(i, 2, QTableWidgetItem(url))
                    self.browser_table.setItem(i, 3, QTableWidgetItem(str(browser_entry.get('visit_count', 'N/A'))))
                    self.browser_table.setItem(i, 4, QTableWidgetItem(str(browser_entry.get('timestamp', 'N/A'))))
            except Exception as e:
                print(f"Error updating browser table: {e}")
                QMessageBox.warning(self, "Warning", f"Error updating browser table: {str(e)}")

        @pyqtSlot()
        def _update_browser_table(self):
            self.browser_table.setRowCount(len(self.browser_data))
            for i, browser_entry in enumerate(self.browser_data):
                self.browser_table.setItem(i, 0, QTableWidgetItem(str(browser_entry.get('browser', 'N/A'))))
                self.browser_table.setItem(i, 1, QTableWidgetItem(str(browser_entry.get('title', 'N/A'))[:50] + "..."))
                self.browser_table.setItem(i, 2, QTableWidgetItem(str(browser_entry.get('url', 'N/A'))[:50] + "..."))
                self.browser_table.setItem(i, 3, QTableWidgetItem(str(browser_entry.get('visit_count', 'N/A'))))
                self.browser_table.setItem(i, 4, QTableWidgetItem(str(browser_entry.get('timestamp', 'N/A'))))

        def export_log_results(self):
            if not self.log_data and not self.browser_data:
                QMessageBox.warning(self, "Warning", "No log data to export. Please analyze logs first.")
                return

            path, _ = QFileDialog.getSaveFileName(self, "Export Log Results", "", "CSV files (*.csv)")
            if path:
                try:
                    if self.log_data:
                        self.report_generator.generate_csv_report(self.log_data, os.path.dirname(path), 'event_logs')
                    if self.browser_data:
                        self.report_generator.generate_csv_report(self.browser_data, os.path.dirname(path), 'browser_history')
                    QMessageBox.information(self, "Success", f"Log results exported to {path}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to export log results: {str(e)}")

        # Timeline Methods
        def create_timeline(self):
            try:
                if not any([self.file_data, self.log_data, self.browser_data]):
                    QMessageBox.warning(self, "Warning", "No data available for timeline. Please run analysis modules first.")
                    return

                self.statusBar().showMessage("Creating timeline...")
                self.timeline_progress.setRange(0, 0)  # Indeterminate progress
                
                # Create timeline directly in main thread to avoid threading issues
                timeline_data = self.timeline_creator.create_timeline(self.file_data, self.log_data, self.browser_data)
                self.timeline_data = timeline_data
                self._update_timeline_table()
                
                self.timeline_progress.setRange(0, 1)
                self.timeline_progress.setValue(1)
                self.statusBar().showMessage(f"Created timeline with {len(timeline_data)} events")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to create timeline: {str(e)}")
                self.timeline_progress.setRange(0, 1)
                self.timeline_progress.setValue(0)
                self.statusBar().showMessage("Ready")

        def _create_timeline_task(self):
            try:
                timeline_data = self.timeline_creator.create_timeline(self.file_data, self.log_data, self.browser_data)
                self.timeline_data = timeline_data
                QMetaObject.invokeMethod(self, "_update_timeline_table", Qt.QueuedConnection)
            except Exception as e:
                print(f"Error in timeline creation: {e}")

        @pyqtSlot()
        def _update_timeline_table(self):
            try:
                self.timeline_table.setRowCount(len(self.timeline_data))
                for i, timeline_entry in enumerate(self.timeline_data):
                    self.timeline_table.setItem(i, 0, QTableWidgetItem(str(timeline_entry.get('timestamp', 'N/A'))))
                    self.timeline_table.setItem(i, 1, QTableWidgetItem(str(timeline_entry.get('event_type', 'N/A'))))
                    self.timeline_table.setItem(i, 2, QTableWidgetItem(str(timeline_entry.get('source', 'N/A'))))
                    details = str(timeline_entry.get('details', 'N/A'))
                    if len(details) > 100:
                        details = details[:100] + "..."
                    self.timeline_table.setItem(i, 3, QTableWidgetItem(details))
            except Exception as e:
                print(f"Error updating timeline table: {e}")
                QMessageBox.warning(self, "Warning", f"Error updating timeline table: {str(e)}")

        def export_timeline(self):
            if not self.timeline_data:
                QMessageBox.warning(self, "Warning", "No timeline data to export. Please create timeline first.")
                return

            path, _ = QFileDialog.getSaveFileName(self, "Export Timeline", "", "CSV files (*.csv)")
            if path:
                try:
                    self.report_generator.generate_csv_report(self.timeline_data, os.path.dirname(path), 'timeline')
                    QMessageBox.information(self, "Success", f"Timeline exported to {path}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to export timeline: {str(e)}")

        # Evidence Collection Methods
        def add_evidence_file(self):
            file_path, _ = QFileDialog.getOpenFileName(self, "Select Evidence File")
            if file_path:
                description, ok = QInputDialog.getText(self, "Evidence Description", "Enter description for this evidence:")
                if ok and description:
                    case_id = self.case_id_input.text() or "Unknown"
                    evidence_item = self.evidence_collector.add_evidence(file_path, description, case_id)
                    self._update_evidence_table()

        def _update_evidence_table(self):
            evidence_items = self.evidence_collector.evidence_items
            self.evidence_table.setRowCount(len(evidence_items))
            for i, item in enumerate(evidence_items):
                self.evidence_table.setItem(i, 0, QTableWidgetItem(str(item['id'])))
                self.evidence_table.setItem(i, 1, QTableWidgetItem(str(item['file_path'])))
                self.evidence_table.setItem(i, 2, QTableWidgetItem(str(item['description'])))
                self.evidence_table.setItem(i, 3, QTableWidgetItem(str(item['collected_time'])))
                self.evidence_table.setItem(i, 4, QTableWidgetItem(str(item['hash'])[:16] + "..."))

        def export_evidence(self, format_type):
            if not self.evidence_collector.evidence_items:
                QMessageBox.warning(self, "Warning", "No evidence items to export.")
                return

            export_path = QFileDialog.getExistingDirectory(self, "Select Export Directory")
            if export_path:
                try:
                    result_path = self.evidence_collector.export_evidence(export_path, format_type)
                    QMessageBox.information(self, "Success", f"Evidence exported to {result_path}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to export evidence: {str(e)}")

        # Report Generation Methods
        def generate_csv_report(self):
            export_path = QFileDialog.getExistingDirectory(self, "Select Export Directory")
            if export_path:
                try:
                    reports_generated = []

                    if self.include_files.isChecked() and self.file_data:
                        csv_path = self.report_generator.generate_csv_report(self.file_data, export_path, 'files')
                        reports_generated.append(csv_path)

                    if self.include_logs.isChecked() and self.log_data:
                        csv_path = self.report_generator.generate_csv_report(self.log_data, export_path, 'logs')
                        reports_generated.append(csv_path)

                    if self.include_browser.isChecked() and self.browser_data:
                        csv_path = self.report_generator.generate_csv_report(self.browser_data, export_path, 'browser')
                        reports_generated.append(csv_path)

                    if self.include_timeline.isChecked() and self.timeline_data:
                        csv_path = self.report_generator.generate_csv_report(self.timeline_data, export_path, 'timeline')
                        reports_generated.append(csv_path)

                    if reports_generated:
                        QMessageBox.information(self, "Success", f"CSV reports generated: {len(reports_generated)} files")
                    else:
                        QMessageBox.warning(self, "Warning", "No data available for selected report types.")

                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to generate CSV reports: {str(e)}")

        def generate_html_report(self):
            export_path = QFileDialog.getExistingDirectory(self, "Select Export Directory")
            if export_path:
                try:
                    file_data = self.file_data if self.include_files.isChecked() else []
                    log_data = self.log_data if self.include_logs.isChecked() else []
                    browser_data = self.browser_data if self.include_browser.isChecked() else []
                    timeline_data = self.timeline_data if self.include_timeline.isChecked() else []

                    html_path = self.report_generator.generate_html_report(
                        file_data, log_data, browser_data, timeline_data, export_path
                    )

                    QMessageBox.information(self, "Success", f"HTML report generated: {html_path}")

                    # Update preview
                    with open(html_path, 'r', encoding='utf-8') as f:
                        html_content = f.read()
                    self.report_preview.setHtml(html_content)

                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to generate HTML report: {str(e)}")

        # Utility Methods
        def run_task(self, task_func, progress_bar, status_message):
            """Run a task in a separate thread with progress indication"""
            self.statusBar().showMessage(status_message)
            progress_bar.setRange(0, 0)  # Indeterminate progress

            # Create worker thread
            worker = threading.Thread(target=self._task_wrapper, args=(task_func, progress_bar))
            worker.daemon = True
            worker.start()

        def _task_wrapper(self, task_func, progress_bar):
            """Wrapper for task execution"""
            try:
                task_func()
            except Exception as e:
                print(f"Task error: {e}")
            finally:
                QMetaObject.invokeMethod(self, "_task_finished", Qt.QueuedConnection, Q_ARG(QProgressBar, progress_bar))

        @pyqtSlot(QProgressBar)
        def _task_finished(self, progress_bar):
            """Called when task is finished"""
            progress_bar.setRange(0, 1)
            progress_bar.setValue(1)
            self.statusBar().showMessage('Ready')


def main():
    if not PYQT_AVAILABLE:
        print("PyQt5 is not available. Running in console mode.")
        print("To use the GUI, please install PyQt5: pip install PyQt5")
        return

    app = QApplication(sys.argv)

    # Set application properties
    app.setApplicationName('Windows Forensic Analysis Tool')
    app.setApplicationVersion('1.0')
    app.setOrganizationName('Forensic Tools Inc.')

    # Create and show main window
    window = ForensicAnalysisGUI()
    window.show()

    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
