import re 
import string 

MIN_LENGTH = 12 
SEQ_LEN = 4
def check_length(password:str) -> list[str]:
	issues =[]
	if len(password) < MIN_LENGTH: 
		issues.append(
		f"Password should be at least {MIN_LENGTH} characters.")
	return issues
	
def check_uppercase(password:str) -> list[str]:
	issues =[]
	if sum(char.isupper() for char in password) < 2:
		issues.append(
		"Password should contain at least two uppercase")
	return issues 

def check_lowercase(password:str) -> list[str]:
	issues =[]
	if sum(char.islower() for char in password) < 2:
		issues.append(
		"Password should contain at least two lowercase")
	return issues 
	
def check_digits(password:str) -> list[str]:
	issues =[]
	if sum(char.isdigit() for char in password) < 2:
		issues.append(
		"Password should contain at least two digits")
	return issues 
	
def check_symbols(password:str) -> list[str]:
	issues = []
	if sum(char in string.punctuation for char in password) < 2: 
		issues.append(
		"Password should contain at least 2 symbols")
	return issues
	
def check_repeated_characters(password: str) -> list[str]:
    """
    Detect three or more consecutive identical characters.
    """
    issues = []
    if re.search(r"(.)\1{2,}", password):
        issues.append(
            "Avoid using three or more consecutive identical characters."
        )
    return issues

def check_sequential_characters(password: str) -> list[str]:
    issues = []
    password = password.lower()
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    numbers = "0123456789"
    reverse_alphabet = alphabet[::-1]
    reverse_numbers = numbers[::-1]

    for i in range(len(password) - SEQ_LEN +1):
        chunk = password[i:i+SEQ_LEN]
        if (
    chunk in alphabet
    or chunk in reverse_alphabet
    or chunk in numbers
    or chunk in reverse_numbers
):
            issues.append(
                "Password contains predictable sequential characters."
            )
            break
    return issues
    
    
def evaluate_custom_rules(password:str) -> dict:
	issues = []
	issues.extend(check_length(password))
	issues.extend(check_uppercase(password))
	issues.extend(check_lowercase(password))
	issues.extend(check_digits(password))
	issues.extend(check_symbols(password))
	issues.extend(check_repeated_characters(password))
	issues.extend(check_sequential_characters(password))
# use of extend instead of append to avoid the whole lists be inserted as one element like nested list	
	return{
	"passed": len(issues) == 0, 
	"issues": issues,
	}
	   	
def main():
	while True:
		password = input("Enter password: ")
		if password.lower() == 'exit':
			break
		result = evaluate_custom_rules(password)
		print(result)
		
if __name__ == "__main__":
	main()
