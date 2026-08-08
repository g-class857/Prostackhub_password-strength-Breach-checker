"""
Entropy calculation module.

This module estimates password entropy based on:
    Entropy = Length × log2(Character Set Size)

It only evaluates the theoretical search space and does NOT
check password popularity or dictionary words. Those checks
are handled by zxcvbn in the strength analysis module.
"""

import math 
import string 

CHARACTER_SETS ={
	"lowercase": len(string.ascii_lowercase),
	"uppercase": len(string.ascii_uppercase), 
	"digits": len(string.digits), 
	"symbols": len(string.punctuation) + 1 # symbols + space
	}

def detect_charset(password: str) -> dict: 
	"""
    Detect which character sets are used in a password.

    Returns:
        dict:
            {
                "lowercase": bool,
                "uppercase": bool,
                "digits": bool,
                "symbols": bool
            }
    """
	return {
		"lowercase": any(c.islower() for c in password), 
		"uppercase": any(c.isupper() for c in password), 
		"digits": any(c.isdigit() for c in password), 
		"symbols": any (c in string.punctuation or c.isspace() for c in password), 
		}
		
 
def calculate_charset_size(charsets: dict)-> int: 
	"""
    Calculate the total character pool size.

    Example:
        lowercase + uppercase + digits
        = 26 + 26 + 10
        = 62
    """
	size = 0 
	for charsets, present in charsets.items(): 
		if present: 
			size+= CHARACTER_SETS[charsets]
	return size
	
	
def calculate_entropy(password: str, charset_size:int) -> float: 
	"""
    Formula:
        Entropy = Length × log2(Character Pool Size)
    """
	if not password or charset_size == 0 :
    		return 0.0
    
	entropy = len(password) * math.log2(charset_size)
	return round(entropy, 2)
    
def classify_entropy(entropy: float) -> str: 
	if entropy < 28: 
		return "Very weak"
	if entropy < 36 : 
		return "Weak"
	if entropy < 60 : 
		return "Reasonable"
	if entropy < 80 : 
		return "Strong"
	return "Very strong"
	
def analyze_password_entropy(password:str) -> dict: 
	charsets = detect_charset(password)
	charset_size = calculate_charset_size(charsets)
	entropy = calculate_entropy(password, charset_size)
	
	return {
	"length": len(password),
	"charsets": charsets,
	"charset_size": charset_size, 
	"entropy": entropy,
	"rating" : classify_entropy(entropy)	
	}
	
##################3

def main(): 
	print("password entropy analyzer")
	while True: 
		password = input("\n Enter your pass (type exit to quite):")
		if password.lower()=="exit":
			print("\n bye bye")
			break
		print(analyze_password_entropy(password))
		
if __name__ == "__main__":
	main()
