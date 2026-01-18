import json
import os
import getpass
import hashlib
import math
import random
import string
from datetime import datetime

DATA_FILE = "check_history.json"

class CredentialChecker:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
        self.history = self.load_history()

    def load_common_passwords(self):
        # Small built-in list (real projects would load from file or use HaveIBeenPwned style bloom filter)
        common = {
            "123456", "password", "12345678", "qwerty", "123456789", "12345",
            "1234", "111111", "1234567", "dragon", "123123", "baseball",
            "abc123", "football", "monkey", "letmein", "696969", "shadow",
            "sunshine", "iloveyou", "princess", "admin", "welcome", "login"
        }
        return common

    def load_history(self):
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "r") as f:
                    return json.load(f)
            except:
                return []
        return []

    def save_history(self):
        with open(DATA_FILE, "w") as f:
            json.dump(self.history, f, indent=2)

    def calculate_entropy(self, password):
        if not password:
            return 0.0
        char_set_size = 0
        if any(c.islower() for c in password):
            char_set_size += 26
        if any(c.isupper() for c in password):
            char_set_size += 26
        if any(c.isdigit() for c in password):
            char_set_size += 10
        if any(c in string.punctuation for c in password):
            char_set_size += len(string.punctuation)
        return len(password) * math.log2(char_set_size) if char_set_size > 0 else 0

    def check_strength(self, password):
        score = 0
        issues = []

        if len(password) < 8:
            issues.append("Too short (<8 characters)")
        elif len(password) >= 12:
            score += 30
        elif len(password) >= 10:
            score += 15

        entropy = self.calculate_entropy(password)
        if entropy < 40:
            issues.append(f"Low entropy (~{entropy:.1f} bits)")
        elif entropy >= 60:
            score += 30

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)

        if has_lower: score += 10
        if has_upper: score += 10
        if has_digit: score += 10
        if has_special: score += 15

        if sum([has_lower, has_upper, has_digit, has_special]) < 3:
            issues.append("Missing character variety")

        return score, issues

    def check_common(self, password):
        if password.lower() in self.common_passwords:
            return True, "Common / leaked password"
        return False, None

    def check_similarity(self, username, password):
        if not username or not password:
            return False, None
        u = username.lower()
        p = password.lower()
        if p in u or u in p or p.startswith(u) or p.endswith(u):
            return True, "Password too similar to username"
        return False, None

    def analyze_credential(self):
        print("\n" + "-"*50)
        username = input("Enter username / email: ").strip()
        password = getpass.getpass("Enter password (hidden): ")

        issues = []
        score = 0

        is_common, msg = self.check_common(password)
        if is_common:
            issues.append(msg)
            score -= 40

        similar, sim_msg = self.check_similarity(username, password)
        if similar:
            issues.append(sim_msg)
            score -= 30

        strength_score, strength_issues = self.check_strength(password)
        score += strength_score
        issues.extend(strength_issues)

        # Final score bounded
        final_score = max(0, min(100, score))

        verdict = "Very Weak" if final_score < 30 else \
                  "Weak" if final_score < 50 else \
                  "Moderate" if final_score < 70 else \
                  "Strong" if final_score < 90 else "Excellent"

        pw_hash = hashlib.sha256(password.encode()).hexdigest()[:16] + "..."

        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "password_hash": pw_hash,
            "score": final_score,
            "verdict": verdict,
            "issues": issues
        }
        self.history.append(entry)
        self.save_history()

        print("\nAnalysis Result:")
        print(f"Username: {username}")
        print(f"Password (hashed): {pw_hash}")
        print(f"Score: {final_score}/100 → {verdict}")
        if issues:
            print("Issues / Warnings:")
            for i in issues:
                print(f"  • {i}")
        else:
            print("No major issues detected.")

    def generate_passphrase(self):
        # Very simple diceware-like (real would use real wordlist)
        words = ["apple", "blue", "cat", "dog", "elephant", "fox", "grape", "horse",
                 "ice", "juice", "kite", "lemon", "moon", "night", "ocean", "panda"]
        length = random.randint(4, 6)
        passphrase = " ".join(random.choice(words) for _ in range(length))
        if random.random() > 0.6:
            passphrase += random.choice(["!", "@", "#", "$", "%"])
        print(f"\nSuggested strong passphrase: {passphrase}")
        print("(For real security use a proper wordlist + random generator)")

    def display_history(self):
        if not self.history:
            print("\nNo analysis history yet.")
            return
        print("\nPrevious Checks (most recent first):")
        for entry in reversed(self.history[-8:]):
            print(f"[{entry['timestamp']}] {entry['username']} → {entry['verdict']} ({entry['score']}/100)")

    def display_menu(self):
        print("\n" + "="*50)
        print("     CREDENTIAL CHECKER & PASSPHRASE GENERATOR")
        print("="*50)
        print("1. Analyze password strength & safety")
        print("2. Generate strong passphrase suggestion")
        print("3. View analysis history")
        print("4. Exit")
        print("="*50)

def main():
    checker = CredentialChecker()
    print("Credential Security Checker – Educational Tool\n")

    while True:
        checker.display_menu()
        choice = input("Choose (1-4): ").strip()

        if choice == "1":
            checker.analyze_credential()
        elif choice == "2":
            checker.generate_passphrase()
        elif choice == "3":
            checker.display_history()
        elif choice == "4":
            print("\nExiting. Use strong, unique passwords!")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()