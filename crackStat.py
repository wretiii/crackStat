import re
import sys
import math
from collections import Counter

def calc_entropy(password):
    N = 94  # Assuming the password can use any of the 94 printable ASCII characters
    L = len(password)
    return L * math.log2(N)

def clean_password(password):
    # Strip leading/trailing non-alphabetic characters but keep internal non-alphanumeric ones
    return re.sub(r'^[^a-zA-Z]+|[^a-zA-Z]+$', '', password)

def analyze_passwords(file_path):
    try:
        with open(file_path, 'r') as file:
            passwords = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return

    total_passwords = len(passwords)

    # Helper function to calculate percentage
    def calc_percentage(count):
        return (count / total_passwords) * 100

    # Top 10 Passwords
    print("Top 10 Passwords:")
    for password, count in Counter(passwords).most_common(10):
        print(f"{password} = {count} ({calc_percentage(count):.2f}%)")

    # Top 10 Base Passwords
    print("\nTop 10 Base Passwords:")
    base_words = [clean_password(password).lower() for password in passwords]
    filtered_base_words = [word for word in base_words if word]
    base_word_counts = Counter(filtered_base_words)
    for word, count in base_word_counts.most_common(10):
        print(f"{word} = {count} ({calc_percentage(count):.2f}%)")

    # Calculate average password length
    average_length = sum(len(password) for password in passwords) / total_passwords if total_passwords > 0 else 0
    print("\nPassword Length:")
    print(f"Average Character Length: {average_length:.2f}")
    length_counts = Counter(len(password) for password in passwords)
    for length, count in length_counts.most_common():
        percentage = calc_percentage(count)
        print(f"{length} characters = {count} ({percentage:.2f}%)")

    # Password length categories
    print()
    length_categories = {
        "1 to 6 characters": sum(count for length, count in length_counts.items() if 1 <= length <= 6),
        "1 to 8 characters": sum(count for length, count in length_counts.items() if 1 <= length <= 8),
        "More than 8 characters": sum(count for length, count in length_counts.items() if length > 8)
    }
    for category, count in length_categories.items():
        print(f"{category} = {count} ({calc_percentage(count):.2f}%)")

    # Character composition
    print()
    char_comp_categories = {
        "Only lowercase alpha": sum(1 for password in passwords if password.isalpha() and password.islower()),
        "Only uppercase alpha": sum(1 for password in passwords if password.isalpha() and password.isupper()),
        "Only alpha": sum(1 for password in passwords if password.isalpha()),
        "Only numeric": sum(1 for password in passwords if password.isnumeric())
    }
    for category, count in char_comp_categories.items():
        print(f"{category} = {count} ({calc_percentage(count):.2f}%)")

    # Starting and ending characters
    print()
    first_capital_last_symbol = sum(1 for password in passwords if password[0].isupper() and not password[-1].isalnum())
    first_capital_last_number = sum(1 for password in passwords if password[0].isupper() and password[-1].isdigit())
    print(f"First capital last symbol = {first_capital_last_symbol} ({calc_percentage(first_capital_last_symbol):.2f}%)")
    print(f"First capital last number = {first_capital_last_number} ({calc_percentage(first_capital_last_number):.2f}%)")

    # Ending with digits
    print()
    ending_with_digits_counts = {i: sum(1 for password in passwords if re.match(r'.*?(\d{' + str(i) + '})\Z', password)) for i in range(1, 5)}
    for digits, count in ending_with_digits_counts.items():
        print(f"{digits} digits on the end = {count} ({calc_percentage(count):.2f}%)")

    # Last digit frequencies
    print("\nLast Digit:")
    last_digit_counts = Counter(password[-1] for password in passwords if password[-1].isdigit())
    for digit, count in last_digit_counts.most_common():
        print(f"{digit} = {count} ({calc_percentage(count):.2f}%)")

    # Analyze last two, three, four, and five digits
    def analyze_last_n_digits(n):
        pattern = re.compile(r'(\d{' + str(n) + '})\Z')  # Regex to match last n digits
        last_n_digit_counts = Counter(pattern.findall(password)[0] for password in passwords if pattern.search(password))
        print(f"\nTop Ten Last {n} Digits:")
        for digits, count in last_n_digit_counts.most_common(10):
            print(f"{digits} = {count} ({calc_percentage(count):.2f}%)")

    # Apply the analysis for 2, 3, 4, and 5 digits
    for n in range(2, 6):
        analyze_last_n_digits(n)

    # Group passwords by entropy and track an example password for each entropy level
    entropy_values = {}
    for password in passwords:
        entropy = calc_entropy(password)
        if entropy not in entropy_values:
            entropy_values[entropy] = {'count': 0, 'example': password}
        entropy_values[entropy]['count'] += 1

    average_entropy = round(sum(calc_entropy(password) for password in passwords) / total_passwords, 4) if total_passwords > 0 else 0
    print(f"\nAverage Password Entropy: {average_entropy:.4f} bits")

    # Sort and prepare for top 5 and bottom 5 listings
    sorted_entropy_groups = sorted(entropy_values.items(), key=lambda item: item[0])

    print("\nPassword Entropy - Top 5:")
    for entropy, data in sorted_entropy_groups[-5:][::-1]:  # Highest to lowest
        percentage = calc_percentage(data['count'])
        print(f"Entropy: {entropy:.4f} bits - Occurrences: {data['count']} ({percentage:.2f}%) - Approximate Length: {len(data['example'])}")

    print("\nPassword Entropy - Bottom 5:")
    for entropy, data in sorted_entropy_groups[:5]:  # Lowest to highest
        percentage = calc_percentage(data['count'])
        print(f"Entropy: {entropy:.4f} bits - Occurrences: {data['count']} ({percentage:.2f}%) - Approximate Length: {len(data['example'])}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py password-file.txt")
    else:
        file_path = sys.argv[1]
        analyze_passwords(file_path)
