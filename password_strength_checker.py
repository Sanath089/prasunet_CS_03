import re
from termcolor import colored

def check_password_strength(password):
    # Criteria for password strength
    length_criteria = len(password) >= 8
    uppercase_criteria = re.search(r'[A-Z]', password) is not None
    lowercase_criteria = re.search(r'[a-z]', password) is not None
    number_criteria = re.search(r'[0-9]', password) is not None
    special_char_criteria = re.search(r'[\W_]', password) is not None

    # Calculate the strength score
    strength_score = sum([length_criteria, uppercase_criteria, lowercase_criteria, number_criteria, special_char_criteria])

    # Determine the password strength
    if strength_score == 5:
        strength = "Very Strong"
    elif strength_score == 4:
        strength = "Strong"
    elif strength_score == 3:
        strength = "Moderate"
    elif strength_score == 2:
        strength = "Weak"
    else:
        strength = "Very Weak"

    # Provide feedback
    feedback = []
    if not length_criteria:
        feedback.append("Password should be at least 8 characters long.")
    if not uppercase_criteria:
        feedback.append("Password should contain at least one uppercase letter.")
    if not lowercase_criteria:
        feedback.append("Password should contain at least one lowercase letter.")
    if not number_criteria:
        feedback.append("Password should contain at least one number.")
    if not special_char_criteria:
        feedback.append("Password should contain at least one special character (e.g., !, @, #, $, etc.).")

    return strength, feedback

def main():
    print(colored("#                ┓            ┓   ┓    ┓                   ", 'red'))
    print(colored("#  ┏┓┏┓┏┏┓┏┏┏┓┏┓┏┫ ┏╋┏┓┏┓┏┓┏┓╋┣┓ ┏┣┓┏┓┏┃┏┏┓┏┓              ", 'green'))
    print(colored("#  ┣┛┗┻┛┛┗┻┛┗┛┛ ┗┻━┛┗┛ ┗ ┛┗┗┫┗┛┗━┗┛┗┗ ┗┛┗┗ ┛               ", 'yellow'))
    print(colored("#  ┛                        ┛            ┓               ┓ ", 'blue'))
    print(colored("#  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┣┓┓┏━━━━┏┏┓┏┓┏┓╋┣┓", 'magenta'))
    print(colored("#                                        ┗┛┗┫    ┛┗┻┛┗┗┻┗┛┗", 'cyan'))
    print(colored("#                                           ┛              ", 'white'))

    while True:
        password = input("Enter a password to check its strength: ")
        strength, feedback = check_password_strength(password)
        
        print(f"Password Strength: {strength}")
        if feedback:
            print("Feedback:")
            for item in feedback:
                print(f"- {item}")
        
        repeat = input("Do you want to check another password? (y/n): ").lower()
        if repeat != 'y':
            break

if __name__ == "__main__":
    main()
