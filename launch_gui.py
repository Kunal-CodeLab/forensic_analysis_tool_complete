#!/usr/bin/env python3
"""
Safe launcher for the Forensic Analysis Tool GUI
This script includes error handling to prevent crashes
"""

import sys
import traceback
from PyQt5.QtWidgets import QApplication, QMessageBox
from forensic_analysis_tool import ForensicAnalysisGUI, PYQT_AVAILABLE

def main():
    """Main launcher function with comprehensive error handling"""
    
    if not PYQT_AVAILABLE:
        print("ERROR: PyQt5 is not available.")
        print("Please install PyQt5: pip install PyQt5")
        input("Press Enter to exit...")
        return 1
    
    try:
        # Create QApplication
        app = QApplication(sys.argv)
        
        # Set application properties
        app.setApplicationName('Windows Forensic Analysis Tool')
        app.setApplicationVersion('1.0')
        app.setOrganizationName('Forensic Tools Inc.')
        
        # Create main window
        print("Starting Forensic Analysis Tool...")
        window = ForensicAnalysisGUI()
        
        # Show window
        window.show()
        
        print("GUI launched successfully!")
        print("Close this console window or press Ctrl+C to exit")
        
        # Start event loop
        return app.exec_()
        
    except Exception as e:
        error_msg = f"Failed to start GUI application: {str(e)}\n\nFull error:\n{traceback.format_exc()}"
        print(error_msg)
        
        # Try to show error in message box if possible
        try:
            app = QApplication.instance()
            if app is None:
                app = QApplication(sys.argv)
            QMessageBox.critical(None, "Application Error", error_msg)
        except:
            pass
        
        input("Press Enter to exit...")
        return 1

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
