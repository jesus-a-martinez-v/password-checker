# Import dependencies
import hashlib
import json
from argparse import ArgumentParser
from http import HTTPStatus

import requests
from simple_colors import red, green, blue

CONFIG_FILE = 'config.json'
CONFIG = None

# Load the config file
with open(CONFIG_FILE, mode='r') as config_file:
    CONFIG = json.load(config_file)


def make_request(query_chars: str):
    """
    Given a password prefix, checks if it's been leaked

    :param query_chars: Password prefix used to check agains the password leak API.
    :return: API's response object.
    """
    assert len(query_chars) == 5, 'Input must be exactly 5 characters long.'

    # Make request to the password checker service.
    url = f'{CONFIG["apiEndpoint"]}/{query_chars}'
    response = requests.get(url)

    # Handle the error properly.
    if response.status_code != HTTPStatus.OK:
        raise RuntimeError(f'Error fetching: {response.status_code}.\n'
                           f'{response.text}.\n'
                           'Check the API and try again.')

    return response


def count_leaks(hashes: str, hash_to_check: str):
    """
    Given the text response of the API, and the tail of the hashed password
    it counts how many leaks were found.
    :param hashes: Text response of the password leaks API.
    :param hash_to_check: Tail of the hashed password.
    :return: Number of leaks found.
    """
    leaked_hashes = hashes.splitlines()

    # Check if there's a match in the response
    for h, count in (line.split(':') for line in leaked_hashes):
        # Return the number of leaks found in the response.
        if h == hash_to_check:
            return int(count)

    return 0


def check_password(password: str):
    """
    Checks if a password has been leaked using PWND's API service.

    :param password: Raw password to check.
    :return: Number of leaks found in PWND's API.
    """
    # Hash the password using SHA1.
    sha1_password = (hashlib
                     .sha1(password.encode('utf-8'))
                     .hexdigest()
                     .upper())

    # The first 5 chars of the digest will be used to check for leaks.
    prefix, tail = sha1_password[:5], sha1_password[5:]
    response = make_request(prefix)

    # We compare the API response with the tail of the input password to find the
    # number of leaks.
    num_leaks = count_leaks(response.text, tail)

    return num_leaks


def get_output_message(leaks):
    """
    Creates a user friendly message based on the number of leaks found.
    """
    if leaks > 0:
        return red(f'🔴{leaks} leaks', ['bold', 'underlined']) + 'You should change it.'

    return green(f'✅ No leaks found!', ['bold', 'underlined'])


def main():
    # Create the menu.
    argument_parser = ArgumentParser()
    argument_parser.add_argument('-p', '--passwords', nargs='+', required=True, help='Password to check')
    arguments = vars(argument_parser.parse_args())

    # Check the passwords, one by one.
    for password in arguments['passwords']:
        leaks = check_password(password)

        # Get the corresponding output messaged based on the number of leaks found.
        message = get_output_message(leaks)

        # We only show the first two chars of the password when printing the message in the console.
        encoded_password = f'{password[:2] + ("*" * (len(password) - 2))}'

        print(blue(encoded_password, ['bold']))
        print(f'\t{message}')


if __name__ == '__main__':
    main()
