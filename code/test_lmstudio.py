# code/test_lmstudio.py
import sys
import os
import json

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import the analyzer
from log_analyzer import LMStudioAnalyzer

def main():
    print("LM Studio Connection Test")
    print("-----------------------")
    
    # Initialize the analyzer
    api_url = input("Enter LM Studio API URL (default: http://localhost:1234/v1): ")
    if not api_url:
        api_url = "http://localhost:1234/v1"
    
    analyzer = LMStudioAnalyzer(api_url=api_url)
    
    # Test connection
    print("\nTesting connection to LM Studio...")
    success, message = analyzer.test_connection()
    print(f"Result: {message}")
    
    if success:
        print("\nConnection successful! Testing log analysis...")
        
        # Get a sample log
        sample_log = "Failed login attempt for admin user from IP 10.0.0.15, 5th attempt in 2 minutes"
        print(f"\nAnalyzing sample log: \"{sample_log}\"")
        
        # Analyze log
        result = analyzer.analyze_log(sample_log)
        
        # Print result
        print("\nAnalysis result:")
        print(json.dumps(result, indent=2))
        
        if result.get("threat_level") != "Error":
            print("\n✅ Log analysis successful!")
        else:
            print("\n❌ Log analysis returned an error.")
    else:
        print("\n❌ Could not connect to LM Studio.")
        print("Please make sure LM Studio is running with the API server enabled.")

if __name__ == "__main__":
    main()