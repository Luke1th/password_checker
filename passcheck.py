import requests      
import hashlib        
import sys
import time  # Added for delay

# Define delay constant (in seconds)
# HIBP recommends at least 1500ms between requests to avoid rate limiting
API_REQUEST_DELAY = 1.5   

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    # Check if the password exists in the API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    
    # Add a delay before making the API request to avoid rate limiting
    time.sleep(API_REQUEST_DELAY)  # Delay to respect HIBP rate limits
    response = request_api_data(first5_char)
    #print(first5_char, tail, response)
    return get_password_leaks_count(response, tail)

def check_common_password(password):
    try:
        with open('common_passwords.txt', 'r', encoding='utf-8') as f:
            common = set(f.read().splitlines())  # Use set for faster lookups
        return password in common
    except FileNotFoundError:
        print("Warning: 'common_passwords.txt' not found. Skipping local common password check.")
        return False
    except IOError:
        print("Error reading 'common_passwords.txt'. Skipping local check.")
        return False

def main(args):
    if not args:
        print("Please provide at least one password as an argument!")
        return 1  # Non-zero exit code for error
    
    # Print header for structured output
    print("\n{:<20} | {:<15} | {}".format("Password", "Status", "Details"))
    print("-" * 60)  # Separator line
    
    for password in args:
        password = password.strip()  # Remove accidental newlines or spaces
        status = "Non-breached password"
        details = "Not found in breach or common_passwords list."
        
        # Check local common password list
        if check_common_password(password):
            status = "Common password"
            details = "Found in common_passwords list. Consider changing it!"
        else:
            # Check HIBP API
            count = pwned_api_check(password)
            if count:
                status = "Data breach"
                details = f"Found {count} times in breaches. Consider changing your password!"

        # Print formatted result with an extra newline
        print(f"{password:<20} | {status:<15} | {details}\n") # Extra newline at the end

    return 0  # Success exit code
    
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

