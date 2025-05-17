# src/log_analyzer.py
import requests
import json
import re
import time
import os

class LMStudioAnalyzer:
    def __init__(self, api_url="http://localhost:1234/v1"):
        self.api_url = api_url
        
    def test_connection(self):
        """Test the connection to LM Studio API"""
        try:
            response = requests.get(
                f"{self.api_url}/models",
                timeout=5
            )
            if response.status_code == 200:
                return True, "Connected to LM Studio API successfully"
            else:
                return False, f"Connection error: Status code {response.status_code}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    def load_prompt_template(self, prompt_name="log_prompt_test4_json.txt"):
        """Load a prompt template from the prompts directory"""
        # Try to find the prompt file in the prompts directory
        prompt_file = os.path.join('prompts', prompt_name)
        if not os.path.exists(prompt_file):
            prompt_file = os.path.join('..', 'prompts', prompt_name)
        
        if os.path.exists(prompt_file):
            with open(prompt_file, 'r') as f:
                return f.read()
        else:
            # Default prompt if file doesn't exist
            return """
            Analyze the following security log entry and determine if it represents a security threat.
            If it is a threat, classify its severity (Critical, High, Medium, Low) and provide a brief explanation.
            If it's not a threat, state "No Threat Detected".
            
            Log entry:
            {log_entry}
            
            Respond in JSON format with the following structure:
            {
                "is_threat": true/false,
                "threat_level": "Critical/High/Medium/Low/None",
                "explanation": "Brief explanation of the threat or why it's not a threat",
                "recommended_action": "Brief recommendation for handling this threat"
            }
            """
    
    def analyze_log(self, log_entry, prompt_template=None):
        """Analyze a log entry using LM Studio API"""
        if prompt_template is None:
            prompt_template = self.load_prompt_template()
        
        # Replace placeholder with actual log entry
        prompt = prompt_template.replace("{log_entry}", log_entry)
        
        try:
            response = requests.post(
                f"{self.api_url}/chat/completions",
                headers={"Content-Type": "application/json"},
                json={
                    "model": "local-model",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                answer = result['choices'][0]['message']['content']
                
                # Try to extract JSON from the answer
                try:
                    # Find anything that looks like JSON in the answer
                    json_match = re.search(r'\{.*\}', answer, re.DOTALL)
                    if json_match:
                        json_str = json_match.group(0)
                        return json.loads(json_str)
                    else:
                        # If no JSON found, parse the whole answer
                        return json.loads(answer)
                except json.JSONDecodeError:
                    # Handle case where model doesn't return valid JSON
                    return {
                        "is_threat": False,
                        "threat_level": "Error",
                        "explanation": "Failed to parse model response: " + answer[:100] + "...",
                        "recommended_action": "Check model configuration"
                    }
            else:
                return {
                    "is_threat": False,
                    "threat_level": "Error",
                    "explanation": f"API Error: {response.status_code}",
                    "recommended_action": "Check LM Studio connection"
                }
                
        except requests.exceptions.RequestException as e:
            return {
                "is_threat": False,
                "threat_level": "Error",
                "explanation": f"Connection Error: {str(e)}",
                "recommended_action": "Check if LM Studio server is running"
            }
        except Exception as e:
            return {
                "is_threat": False,
                "threat_level": "Error",
                "explanation": f"Exception: {str(e)}",
                "recommended_action": "Check network connection"
            }

    def batch_analyze(self, logs, max_retries=3):
        """Analyze a batch of logs and return results"""
        results = []
        for log in logs:
            # Try up to max_retries times in case of errors
            for attempt in range(max_retries):
                try:
                    analysis = self.analyze_log(log)
                    if analysis.get("threat_level") != "Error":
                        results.append(analysis)
                        break
                    else:
                        # Wait before retrying
                        time.sleep(1)
                except Exception as e:
                    if attempt == max_retries - 1:
                        results.append({
                            "is_threat": False,
                            "threat_level": "Error",
                            "explanation": f"Failed after {max_retries} attempts: {str(e)}",
                            "recommended_action": "Check system configuration"
                        })
                    time.sleep(1)
        return results

    def save_results(self, results, filename="log_analysis_results.json"):
        """Save analysis results to a JSON file"""
        with open(os.path.join('data', filename), 'w') as f:
            json.dump(results, f, indent=2)