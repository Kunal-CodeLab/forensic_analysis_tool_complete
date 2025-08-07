#!/usr/bin/env python3
"""
Test script to verify the recycle bin scan fix
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_recycle_bin_scan():
    """Test the recycle bin scanning functionality"""
    try:
        from forensic_analysis_tool import FileRecoveryEngine
        
        print("Testing FileRecoveryEngine...")
        recovery = FileRecoveryEngine()
        
        print("Scanning recycle bin...")
        recycle_files = recovery.scan_recycle_bin()
        
        print(f"✅ Successfully scanned recycle bin: {len(recycle_files)} files found")
        
        # Test a few files
        for i, file_info in enumerate(recycle_files[:3]):
            print(f"  File {i+1}: {file_info.get('name', 'N/A')} ({file_info.get('source', 'N/A')})")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in recycle bin scan: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_gui_components():
    """Test GUI components without showing the window"""
    try:
        from forensic_analysis_tool import PYQT_AVAILABLE
        
        if not PYQT_AVAILABLE:
            print("⚠️  PyQt5 not available, skipping GUI test")
            return True
            
        from PyQt5.QtWidgets import QApplication
        from forensic_analysis_tool import ForensicAnalysisGUI
        
        # Create application (required for PyQt)
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
        
        print("Testing GUI initialization...")
        window = ForensicAnalysisGUI()
        
        print("Testing recycle bin scan method...")
        # Test the scan method directly
        window.scan_recycle_bin()
        
        print(f"✅ GUI scan method completed: {len(window.file_data)} files found")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in GUI test: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("🧪 Testing Recycle Bin Scan Fix")
    print("=" * 40)
    
    tests = [
        ("File Recovery Engine", test_recycle_bin_scan),
        ("GUI Components", test_gui_components)
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\n🔍 {test_name}...")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                failed += 1
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            failed += 1
            print(f"❌ {test_name}: CRITICAL FAILURE - {e}")
    
    print("\n" + "=" * 40)
    print("🏁 Fix Test Summary")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    
    if failed == 0:
        print("🎉 All fixes working correctly! The recycle bin scan should no longer crash.")
    else:
        print("⚠️  Some issues remain. Please check the errors above.")
    
    return failed

if __name__ == '__main__':
    exit_code = main()
    print(f"\nPress Enter to exit...")
    input()
    sys.exit(exit_code)
