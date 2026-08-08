from zxcvbn import zxcvbn
from modules.entropy import analyze_password_entropy

"""
This module combines:
- Entropy analysis
- zxcvbn analysis
- Custom security rules

to produce a comprehensive password security report.
"""

def analyze_zxcvbn(password: str) -> dict:
	return zxcvbn(password)
		
def extract_zxcvbn_results(password: str) -> dict:

    result = analyze_zxcvbn(password)
    return {
        "score": result["score"],
        "feedback": result["feedback"],
        "guesses": int(result["guesses"]),
        "crack_time": result["crack_times_display"],
        "sequence": result["sequence"]
    }	

def display_results(result:dict):
	print("Password strength checker")
	print(f"Score	: {result['score']}/4")
	print(f"Guesses	: {result['guesses']}")
	
	print("\nEstimated Crack Time")

	print(
        	f"Offline Attack : "
        	f"{result['crack_time']['offline_fast_hashing_1e10_per_second']}"
    	)

	print(
        f"Online Attack  : "
        f"{result['crack_time']['online_throttling_100_per_hour']}"
    	)

	warning = result["feedback"]["warning"]

	if warning:
		print("\nWarning:")
		print(f"• {warning}")

	suggestions = result["feedback"]["suggestions"]
	if suggestions:
		print("\nSuggestions:")
		for suggestion in suggestions:
			print(f"• {suggestion}")

	print("\nDetected Patterns:")
	for pattern in result["sequence"]:
		print(f"• {pattern['pattern']} → {pattern['token']}")

def main():
	while True:
		password = input("\n Enter password")
		if password.lower()=="exit":
			break
			
		result = extract_zxcvbn_results(password)
		return display_results(result)	
		
if __name__ == "__main__":
	main()
