#!/usr/bin/env python3
"""
Password Strength Checker Tool
Created by Samwel Senso (Mrsenso) - Cyber Security Researcher
A comprehensive tool to evaluate password security
"""

import re
import sys
import argparse
import getpass
import time
from typing import Dict, List, Tuple
import hashlib
import os

class PasswordStrengthChecker:
    def __init__(self):
        self.common_passwords = self._load_common_passwords()
        
    def _load_common_passwords(self) -> set:
        """Load common passwords from a built-in list"""
        common = {
            'password', '123456', '12345678', '1234', 'qwerty', '12345',
            'dragon', 'baseball', 'football', 'letmein', 'monkey',
            'mustang', 'michael', 'shadow', 'master', 'jennifer',
            '111111', '2000', 'jordan', 'superman', 'harley', '1234567',
            'freedom', 'matrix', 'trustno1', 'killer', 'welcome'
        }
        return common

    def show_banner(self):
        """Display the creator banner"""
        banner = r"""
  ____                                    
 |  _ \ __ _ ___ ___      _____  _ __ ___ 
 | |_) / _` / __/ __|____/ _ \ \/ / '__/ _ \
 |  __/ (_| \__ \__ \___|  __/>  <| | |  __/
 |_|   \__,_|___/___/    \___/_/\_\_|  \___|
 
 +---------------------------------------------+
 |        PASSWORD STRENGTH CHECKER            |
 |                                             |
 |        Created by: Samwel Senso             |
 |            (Mrsenso)                        |
 |                                             |
 |       Cyber Security Researcher             |
 +---------------------------------------------+
        """
        print(banner)
        time.sleep(1)  # Pause for dramatic effect

    def check_length(self, password: str) -> Tuple[int, str]:
        """Check password length"""
        length = len(password)
        if length < 8:
            return 0, f"Too short ({length} characters)"
        elif length < 12:
            return 1, f"Moderate length ({length} characters)"
        else:
            return 2, f"Good length ({length} characters)"

    def check_complexity(self, password: str) -> Tuple[int, List[str]]:
        """Check character diversity"""
        checks = []
        score = 0
        
        # Check for lowercase letters
        if re.search(r'[a-z]', password):
            checks.append("Contains lowercase letters")
            score += 1
        
        # Check for uppercase letters
        if re.search(r'[A-Z]', password):
            checks.append("Contains uppercase letters")
            score += 1
        
        # Check for digits
        if re.search(r'\d', password):
            checks.append("Contains digits")
            score += 1
        
        # Check for special characters
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            checks.append("Contains special characters")
            score += 1
        
        return score, checks

    def check_common(self, password: str) -> Tuple[bool, str]:
        """Check if password is common"""
        if password.lower() in self.common_passwords:
            return True, "Password is too common"
        return False, "Not a common password"

    def check_sequential(self, password: str) -> Tuple[bool, str]:
        """Check for sequential characters"""
        # Check for sequential numbers
        if re.search(r'123|234|345|456|567|678|789|890', password):
            return True, "Contains sequential numbers"
        
        # Check for sequential letters
        if re.search(r'abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz', password.lower()):
            return True, "Contains sequential letters"
        
        return False, "No sequential patterns detected"

    def check_repetition(self, password: str) -> Tuple[bool, str]:
        """Check for repeated characters"""
        if re.search(r'(.)\1{2,}', password):
            return True, "Contains repeated characters"
        return False, "No excessive repetition"

    def calculate_entropy(self, password: str) -> Tuple[float, str]:
        """Calculate password entropy"""
        char_set = 0
        if any(c.islower() for c in password):
            char_set += 26
        if any(c.isupper() for c in password):
            char_set += 26
        if any(c.isdigit() for c in password):
            char_set += 10
        if any(not c.isalnum() for c in password):
            char_set += 32  # Common special characters
        
        if char_set == 0:
            return 0.0, "No character diversity"
        
        entropy = len(password) * (char_set.bit_length())
        return entropy, f"Entropy: {entropy:.2f} bits"

    def check_strength(self, password: str) -> Dict:
        """Comprehensive password strength analysis"""
        results = {
            'password': password,
            'length_score': 0,
            'complexity_score': 0,
            'is_common': False,
            'has_sequential': False,
            'has_repetition': False,
            'entropy': 0.0,
            'overall_score': 0,
            'recommendations': []
        }

        # Perform all checks
        length_score, length_msg = self.check_length(password)
        results['length_score'] = length_score
        results['recommendations'].append(length_msg)

        complexity_score, complexity_msgs = self.check_complexity(password)
        results['complexity_score'] = complexity_score
        results['recommendations'].extend(complexity_msgs)

        is_common, common_msg = self.check_common(password)
        results['is_common'] = is_common
        results['recommendations'].append(common_msg)

        has_sequential, seq_msg = self.check_sequential(password)
        results['has_sequential'] = has_sequential
        results['recommendations'].append(seq_msg)

        has_repetition, rep_msg = self.check_repetition(password)
        results['has_repetition'] = has_repetition
        results['recommendations'].append(rep_msg)

        entropy, entropy_msg = self.calculate_entropy(password)
        results['entropy'] = entropy
        results['recommendations'].append(entropy_msg)

        # Calculate overall score (0-100)
        results['overall_score'] = self._calculate_overall_score(results)
        
        return results

    def _calculate_overall_score(self, results: Dict) -> int:
        """Calculate overall password score (0-100)"""
        score = 0
        
        # Length contributes up to 30 points
        score += results['length_score'] * 10
        
        # Complexity contributes up to 40 points (4 categories * 10)
        score += results['complexity_score'] * 10
        
        # Penalties
        if results['is_common']:
            score -= 30
        if results['has_sequential']:
            score -= 15
        if results['has_repetition']:
            score -= 10
        
        # Entropy bonus (up to 20 points)
        entropy_bonus = min(results['entropy'] / 5, 20)
        score += entropy_bonus
        
        return max(0, min(100, int(score)))

    def display_results(self, results: Dict):
        """Display the results in a formatted way"""
        print("\n" + "="*60)
        print("PASSWORD STRENGTH ANALYSIS")
        print("="*60)
        
        print(f"Password: {'*' * len(results['password'])}")
        print(f"Overall Score: {results['overall_score']}/100")
        
        # Rating
        if results['overall_score'] >= 80:
            rating = "VERY STRONG"
            color = "\033[92m"  # Green
        elif results['overall_score'] >= 60:
            rating = "STRONG"
            color = "\033[94m"  # Blue
        elif results['overall_score'] >= 40:
            rating = "MODERATE"
            color = "\033[93m"  # Yellow
        elif results['overall_score'] >= 20:
            rating = "WEAK"
            color = "\033[91m"  # Red
        else:
            rating = "VERY WEAK"
            color = "\033[91m"  # Red
        
        print(f"Rating: {color}{rating}\033[0m")
        print(f"Entropy: {results['entropy']:.2f} bits")
        
        print("\nDETAILS:")
        print("-" * 40)
        for rec in results['recommendations']:
            print(f"• {rec}")
        
        print("\nRECOMMENDATIONS:")
        print("-" * 40)
        if results['overall_score'] < 60:
            print("• Use at least 12 characters")
            print("• Mix uppercase, lowercase, numbers, and symbols")
            print("• Avoid common words and patterns")
            print("• Consider using a passphrase")
        else:
            print("• Good job! Your password is strong")
            print("• Consider using a password manager")
            print("• Enable two-factor authentication where possible")

def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument('-p', '--password', help='Password to check')
    parser.add_argument('-f', '--file', help='File containing passwords to check')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    parser.add_argument('-n', '--no-banner', action='store_true', help='Skip banner display')
    
    args = parser.parse_args()
    checker = PasswordStrengthChecker()
    
    # Show banner unless disabled
    if not args.no_banner:
        checker.show_banner()
    
    if args.interactive or (not args.password and not args.file):
        print("Interactive Password Strength Checker")
        print("Enter passwords to check (press Ctrl+C to exit)")
        
        while True:
            try:
                password = getpass.getpass("\nEnter password: ")
                if not password:
                    continue
                
                results = checker.check_strength(password)
                checker.display_results(results)
                
            except KeyboardInterrupt:
                print("\n\nExiting...")
                break
    
    elif args.password:
        results = checker.check_strength(args.password)
        checker.display_results(results)
    
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            for password in passwords:
                results = checker.check_strength(password)
                checker.display_results(results)
                print("\n" + "="*60 + "\n")
                
        except FileNotFoundError:
            print(f"Error: File {args.file} not found")
        except Exception as e:
            print(f"Error reading file: {e}")

if __name__ == "__main__":
    main()