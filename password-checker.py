import requests
import hashlib
import sys
import os
from requests.models import Response


def request_api_data(query_char):
    # the second string is first 5 letter of the sha1 hash of 'password123'
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    # which is for K-anonymity
    res = requests.get(url)
    if res.status_code != 200:  # response code of 200 means it its working properly and 400 is an error
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check and try again !')
    return res


#  param hashes - the response from the API
#  param hash_to_check - is the rest of the hash that we didn't send to the API
def get_password_leaks_count(hashes, hash_to_check):
    # Splits hashes with their count and add it to a tuple
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


# param password - the password to check.
def pwned_api_check(password):
    # the password is converted to a sha1 hash
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    # Only the first 5 char of hash are sent to API
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(passwords):
    for password in passwords:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times. Change it !!')
        else:
            print(f'{password} is good to go !!!')
    print('All done !!')


if __name__ == '__main__':
    file = sys.argv[1]

    # putting a txt file of password rather than inputting in the command line to make it more secure.
    with open(file, 'r') as password_list:
        password = password_list.read().splitlines()
        sys.exit(main(password))
