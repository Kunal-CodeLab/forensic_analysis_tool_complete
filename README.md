# Windows Forensic Analysis Tool

A comprehensive, production-ready forensic investigation tool with a modern PyQt5 GUI interface. This tool provides five core forensic analysis modules for Windows systems, designed for legal investigation and digital evidence collection.

## 🚀 Features

### ✅ Deleted File Recovery
- **Recycle Bin Recovery**: Scan and recover files from Windows Recycle Bin
- **NTFS Deleted File Scan**: Attempt recovery of accidentally deleted files using MFT analysis
- **File Metadata Extraction**: Timestamps, file sizes, SHA-256 hashes
- **Cross-platform Compatibility**: Works on Windows, Linux, and macOS

### ✅ Log Analysis
- **Windows Event Logs**: Analyze Security, System, and Application logs
- **Browser History Extraction**: 
  - Google Chrome history and metadata
  - Mozilla Firefox browsing history
  - Microsoft Edge browsing data
- **Application Logs**: Parse available application-specific logs
- **Automated Processing**: Bulk analysis with progress tracking

### ✅ Timeline Creation
- **Chronological Activity Mapping**: User login/logout events
- **File System Activity**: File creation, modification, access timestamps  
- **Web Browsing Timeline**: Visited URLs with timestamps
- **System Events**: Correlated system and application events
- **Interactive Timeline View**: Sortable and filterable results

### ✅ Evidence Collection
- **Chain of Custody**: Automated evidence tracking with metadata
- **File Hash Verification**: SHA-256 integrity checking
- **Export Formats**: 
  - ZIP archives with organized structure
  - Folder exports with file organization
- **Metadata Preservation**: Original timestamps and file attributes
- **Investigation Reports**: JSON-formatted custody records

### ✅ Professional Reporting
- **CSV Export**: Structured data for analysis tools
- **HTML Reports**: Professional, legally-formatted reports with:
  - Investigation summary and statistics
  - Organized data tables with proper headings
  - Timestamp correlation and analysis
  - Evidence chain documentation
- **Report Templates**: Standardized formatting for legal proceedings

## 🖥️ GUI Interface

### Modern PyQt5 Design
- **Sidebar Navigation**: Intuitive module selection
- **Tabbed Interface**: Organized workflow management
- **Progress Indicators**: Real-time operation feedback
- **Status Updates**: Informative progress messaging
- **Results Tables**: Sortable, filterable data presentation
- **Export Controls**: One-click evidence and report generation

### User Experience
- **Clean Interface**: Professional, distraction-free design
- **Responsive Layout**: Adaptive to different screen sizes
- **Error Handling**: Graceful failure recovery with user notifications
- **Threading**: Non-blocking operations for smooth performance

## 📋 System Requirements

- **Operating System**: Windows 10/11 (recommended), Windows 7+
- **Python Version**: Python 3.6 or higher
- **Memory**: Minimum 4GB RAM (8GB+ recommended for large datasets)
- **Storage**: 1GB free space for temporary files and exports
- **Privileges**: Administrator rights (recommended for full functionality)

## 🔧 Installation & Setup

## 🔧 Quick Installation (One Click Setup)

### 🔹 Recommended for Windows Users
1. Extract all files to a folder (e.g., `C:\ForensicTool\`)
2. Double-click **`one_click_setup.bat`**
3. The tool will:
   - Auto-install Python (if not already installed)
   - Install required libraries
   - Launch the tool GUI (`launch_gui.py`)

> ✅ No need to install anything manually!

---

## 🖐 Manual Installation (Advanced Users)
1. Extract all files
2. Open CMD in the extracted folder
3. Run:
   ```
   pip install pandas psutil pyautogui
   ```
4. Then:
   ```
   python launch_gui.py
   ```

---

## ✅ To Test the Tool
Run the following to validate:
```
python test_forensic_tool.py
```

### Dependencies
- **PyQt5**: GUI framework and interface components
- **send2trash**: Cross-platform recycle bin operations  
- **python-evtx**: Windows Event Log (.evtx) parsing
- **browser-history**: Multi-browser history extraction
- **Standard Library**: sqlite3, csv, json, hashlib, threading

## 🎯 Usage Guide

### 1. File Recovery Module
1. **Navigate** to File Recovery tab
2. **Scan Recycle Bin**: Click "Scan Recycle Bin" for deleted file recovery
3. **Scan Deleted Files**: Click "Scan Deleted Files" for NTFS analysis
4. **Review Results**: Examine recovered files in the results table
5. **Export Results**: Save findings to CSV for further analysis

### 2. Log Analysis Module
1. **Open** Log Analysis tab
2. **Analyze Event Logs**: Extract Windows system, security, and application logs
3. **Extract Browser History**: Recover browsing data from Chrome, Firefox, Edge
4. **Review Data**: Use sub-tabs to examine different log types
5. **Export Findings**: Save log analysis results

### 3. Timeline Creation
1. **Ensure Data Collection**: Run File Recovery and Log Analysis first
2. **Create Timeline**: Click "Create Timeline" to correlate all data
3. **Review Timeline**: Examine chronological user and system activity
4. **Export Timeline**: Save timeline for investigation documentation

### 4. Evidence Collection
1. **Set Case ID**: Enter investigation case identifier
2. **Add Evidence**: Select relevant files for evidence collection
3. **Review Chain of Custody**: Verify evidence metadata and hashes
4. **Export Evidence**: 
   - **ZIP Archive**: Compressed evidence package
   - **Folder Structure**: Organized file system export

### 5. Report Generation
1. **Select Data Sources**: Choose which analysis results to include
2. **Generate CSV Reports**: Create structured data files for analysis
3. **Generate HTML Report**: Professional investigation report
4. **Review Output**: Examine generated reports before distribution

## 📊 Technical Architecture

### Core Components

#### FileRecoveryEngine
- **Recycle Bin Scanning**: Multi-platform recycle bin analysis
- **NTFS File Recovery**: Master File Table parsing for deleted files
- **Metadata Extraction**: Comprehensive file attribute collection
- **Hash Calculation**: SHA-256 integrity verification

#### LogAnalyzer  
- **Event Log Parsing**: Windows .evtx file processing via PowerShell
- **Browser Database Analysis**: SQLite database parsing for history
- **Cross-Browser Support**: Unified interface for multiple browsers
- **Temporal Correlation**: Timestamp standardization across sources

#### TimelineCreator
- **Multi-Source Integration**: File system, logs, and browser data correlation
- **Chronological Sorting**: Timestamp-based event ordering  
- **Event Classification**: Activity type categorization
- **Interactive Presentation**: GUI table with sorting and filtering

#### EvidenceCollector
- **Chain of Custody**: Automated evidence tracking with timestamps
- **File Integrity**: Hash-based verification and validation
- **Export Management**: Multiple format support with metadata preservation
- **Legal Compliance**: Investigation-ready documentation standards

#### ReportGenerator
- **Multiple Formats**: CSV and HTML export capabilities
- **Template System**: Consistent, professional report formatting
- **Data Integration**: Multi-source report compilation
- **Metadata Inclusion**: Complete investigation context preservation

### Security Considerations
- **File Integrity**: SHA-256 hashing for evidence verification
- **Metadata Preservation**: Original file attributes maintained
- **Chain of Custody**: Comprehensive evidence tracking
- **Error Handling**: Graceful failure management without data corruption
- **Permission Handling**: Appropriate privilege escalation warnings

## 📁 Output Files

### CSV Reports
- **Structured Data**: Machine-readable format for analysis tools
- **Timestamp Standardization**: Consistent datetime formatting
- **Complete Metadata**: All available file and log attributes
- **Investigation Ready**: Compatible with forensic analysis software

### HTML Reports
- **Professional Layout**: Court-ready presentation format
- **Summary Statistics**: Investigation overview and key metrics
- **Organized Tables**: Categorized findings with clear headers
- **Visual Design**: Clean, readable formatting for legal documentation
- **Embedded Metadata**: Investigation context and system information

### Evidence Packages
- **ZIP Archives**: Compressed evidence with chain of custody documentation
- **Folder Exports**: Organized file structure with metadata preservation
- **JSON Metadata**: Machine-readable evidence tracking
- **Hash Verification**: Integrity checking for all collected files

## ⚖️ Legal Compliance

### Chain of Custody
- **Automated Tracking**: Timestamp and user documentation
- **Hash Verification**: File integrity assurance
- **Metadata Preservation**: Original file attributes maintained
- **Investigation Context**: Case ID and investigator information

### Evidence Standards
- **Non-Destructive Analysis**: Read-only operations on source data
- **Integrity Verification**: SHA-256 hash checking throughout process
- **Audit Trail**: Complete operation logging for legal review
- **Professional Documentation**: Court-ready report formatting

## 🔍 Troubleshooting

### Common Issues

#### PyQt5 Installation Problems
```bash
# Alternative installation methods
pip install --user PyQt5
conda install pyqt
```

#### Permission Errors
- **Run as Administrator**: Right-click → "Run as administrator"
- **UAC Settings**: Adjust User Account Control if needed
- **Antivirus**: Whitelist the tool directory

#### Database Lock Errors (Browser History)
- **Close Browsers**: Ensure all browser instances are closed
- **File Permissions**: Check database file access permissions
- **Temporary Files**: Clear browser cache if needed

#### Event Log Access Issues
- **Administrator Rights**: Required for full event log access
- **Windows Version**: Some features require Windows 7+
- **PowerShell Execution**: Ensure PowerShell execution policy allows scripts

### Performance Optimization
- **Large Datasets**: Process in smaller batches for memory management
- **SSD Storage**: Use solid-state drives for faster file I/O
- **Memory**: Minimum 8GB RAM recommended for large investigations
- **Threading**: Background processing prevents GUI freezing

## 📞 Support & Maintenance

### Regular Updates
- **Dependency Management**: Keep libraries updated for security
- **Windows Compatibility**: Test with new Windows versions
- **Browser Support**: Update database schemas for new browser versions
- **Security Patches**: Apply updates for vulnerability fixes

### Customization Options
- **Report Templates**: Modify HTML templates for organization branding
- **Export Formats**: Add custom export formats as needed
- **Database Schemas**: Update for new browser versions
- **Log Sources**: Extend support for additional log types

## 🏗️ Development Notes

### Code Structure
- **Modular Design**: Separate classes for each major function
- **Error Handling**: Comprehensive exception management
- **Threading**: Background operations for responsive GUI
- **Cross-Platform**: Compatible code for multiple operating systems

### Extension Points
- **New Browsers**: Add browser history extractors
- **Additional Logs**: Extend log parsing capabilities  
- **Export Formats**: Implement additional report formats
- **Database Support**: Add support for other forensic databases

### Testing Considerations
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow validation
- **Performance Tests**: Large dataset handling verification
- **Security Tests**: Evidence integrity validation

## 📄 License & Disclaimer

This tool is provided for legitimate forensic investigation purposes only. Users are responsible for compliance with applicable laws and regulations. The software is provided "as-is" without warranties. Always follow proper legal procedures and obtain appropriate authorization before conducting forensic investigations.

### Usage Compliance
- **Legal Authorization**: Obtain proper warrants/permissions
- **Jurisdictional Laws**: Follow local and federal regulations
- **Privacy Rights**: Respect individual privacy protections
- **Professional Standards**: Adhere to forensic best practices

---

**Version**: 1.0  
**Last Updated**: August 2025  
**Compatibility**: Windows 7+, Python 3.6+  
**License**: Educational/Professional Use
