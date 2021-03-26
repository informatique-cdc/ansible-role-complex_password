#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2021 Informatique CDC. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License

from __future__ import absolute_import, division, print_function
import string
import binascii
from os import urandom as _urandom
from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: complex_password
short_description: Creates a random and complex password with rules
author:
  - Stéphane Bilqué (@sbilque)
description:
  - Ansible module to randomly generate a complex and strong password that match sets of rules.

options:
  length:
    description:
      - The number of characters in the generated password. 
      - The length must be between C(1) and C(128) characters.
    default: 12
    required: 'No'
    type: int
  min_upper_case:
    description:
      - The minimum number of uppercase letters of European languages (C(A) through C(Z)) in the newly generated password.
      - To exclude upper case characters from the password, specify C(-1).
    default: 2
    required: 'No'
    type: int
  min_lower_case:
    description:
      - The minimum number of lowercase letters of European languages (C(a) through C(z)) in the newly generated password.
      - To exclude lower case characters from the password, specify C(-1).
    default: 2
    required: 'No'
    type: int
  min_digit:
    description:
      - The minimum number of characters from base 10 digits (C(0) through C(9)) in the newly generated password. 
      - To exclude digits from the password, specify C(-1).
    default: 2
    required: 'No'
    type: int
  min_special:
    description:
      - The minimum number of non-alphanumeric characters (special characters) in the newly generated password.
      - To exclude special characters from the password, specify C(-1).
    default: 2
    required: 'No'
    type: int
  special_characters:
    description:
      - A string containing all special characters allowed to use.
    default: |-
        /*!\\"$%()=?{[]}+\#-.,<'_:;>~\|@
    required: 'No'
    type: str
  forbidden_characters:  
    description:
      -  The characters that cannot be used when generating a new password, e.g C(/~\).
    required: 'No'
    type: str
  prevent_repeating_characters:
    description:
      - Whether or not characters can be used more than once in a password.
    required: 'No'
    type: bool 
    default: true              
'''
EXAMPLES = r'''
- hosts: localhost

  roles:
    - role: complex_password

  tasks:

    - name: generate a complex password
      complex_password:
        length: 14
        min_upper_case: 3
        min_lower_case: 2
        min_digit: 1
        min_special: 4
        special_characters: '+-'
        prevent_repeating_characters: no

    - name: debug message
      debug:
        var: complex_password

    - name: generate a complex password
      complex_password:
        length: 14
        min_upper_case: 5
        min_lower_case: -1
        min_digit: 3
        min_special: 1
        forbidden_chars: aA0
      register: my_complex_password

    - name: debug message
      debug:
        var: my_complex_password.ansible_facts.complex_password
'''

RETURN = r'''
ansible_facts:
  description: A string containing the password in plain text.
  returned: success
  type: complex
  contains:
    complex_password:
      description: A string containing the password in plain text.
      returned: success
      type: str
'''

SPECIAL_CHARACTERS = "/*!\"$%()=?{[]}+#-.,<'_:;>~|@"

# https://github.com/HacKanCuBa/passphrase-py/blob/master/passphrase/random.py

DEFAULT_ENTROPY = 32  # number of bytes to return by default


def randbytes(nbytes=None):
    r"""Return a random byte string containing *nbytes* bytes.
    Raises ValueError if nbytes <= 0, and TypeError if it's not an integer.
    >>> randbytes(16)  #doctest:+SKIP
    b'\\xebr\\x17D*t\\xae\\xd4\\xe3S\\xb6\\xe2\\xebP1\\x8b'
    """

    if nbytes is None:
        nbytes = DEFAULT_ENTROPY

    if not isinstance(nbytes, int):
        raise TypeError('number of bytes shoud be an integer')
    if nbytes <= 0:
        raise ValueError('number of bytes must be greater than zero')

    return _urandom(nbytes)


def randint(nbits=None):
    r"""Generate an int with nbits random bits.
    Raises ValueError if nbits <= 0, and TypeError if it's not an integer.
    >>> randint()  #doctest:+SKIP
    1871
    """

    if nbits is None:
        nbits = DEFAULT_ENTROPY * 8

    if not isinstance(nbits, int):
        raise TypeError('number of bits should be an integer')
    if nbits <= 0:
        raise ValueError('number of bits must be greater than zero')

    # https://github.com/python/cpython/blob/3.6/Lib/random.py#L676
    nbytes = (nbits + 7) // 8                       # bits / 8 and rounded up
    b = randbytes(nbytes)
    try:
        num = int.from_bytes(b, 'big')
    except:
        num = int(binascii.hexlify(b), 16)
    return num >> (nbytes * 8 - nbits)              # trim excess bits


def mkpasswd(length=12, min_digit=2, min_upper_case=2, min_lower_case=2, min_special=2, special_chars=SPECIAL_CHARACTERS, forbidden_chars="", prevent_repeating_chars=True):
    r"""Create a random password

    Create a random password with the specified length and no. of
    digit, special, upper and lower case letters.

    :param length: The length of the passwords that will be generated.
    :type length: int

    :param min_digit: The minimal number of digital characters (0-9) to include in generated passwords.
    :type min_digit: int

    :param min_upper_case: The minimum number of upper case characters (A-Z) to include in the password.
    :type min_upper_case: int

    :param min_lower_case: The minimum number of lower case characters (a-z) to include in the password.
    :type min_lower_case: int

    :param min_special: The minimal number of special characters to include in generated passwords.
    :type min_special: int

    :param special_chars: A list of special characters to include in generated passwords.
    :type special_chars: str

    :param forbidden_chars: A list of characters that cannot be included in generated passwords.
    :type forbidden_chars: string

    :param prevent_repeating_chars: Whether or not characters can be used more than once in a password.
    :type prevent_repeating_chars: bool

    :returns: A random password with the above constaints
    :rtype: str

    :Example:

    print(mkpasswd(length=12, min_digit=-1, min_upper_case=2, min_lower_case=2,
                min_special=-1, forbidden_chars="abc",prevent_repeating_chars=False))))
    print(mkpasswd(length=8, min_digit=1, min_upper_case=2, min_lower_case=1,
                min_special=-1))
    print(mkpasswd(12))
    print(mkpasswd(min_digit=3))
    print(mkpasswd(12, min_upper_case=4))
    """

    excluded = list(forbidden_chars)

    lower_case = list(set(list(string.ascii_lowercase))-set(excluded))
    upper_case = list(set(list(string.ascii_uppercase))-set(excluded))
    digits = list(set(list(string.digits))-set(excluded))
    special = list(set(list(special_chars))-set(excluded))

    char_groups = [
        {'min': min_lower_case, 'characters': lower_case},
        {'min': min_upper_case, 'characters': upper_case},
        {'min': min_digit, 'characters': digits},
        {'min': min_special, 'characters': special}
    ]

    all_chars = []
    password_min_length = 0
    for group in char_groups:
        if group['min'] > 0:
            password_min_length += group['min']
            all_chars.extend(group['characters'])

    if password_min_length > length:
        raise ValueError(
            'length is lower than the sum of all minimum number of characters from rules')

    if prevent_repeating_chars:
        if length > len(all_chars):
            raise ValueError(
                "Characters can not be used more than once in a password and the length of the password is greater than the total number of characters available to generate this password.")
        if min_lower_case > len(lower_case):
            raise ValueError(
                "lower case characters can not be used more than once in a password and min_lower_case is greater than the number of lower case characters available to generate this password.")
        if min_upper_case > len(upper_case):
            raise ValueError(
                "upper case characters can not be used more than once in a password and min_upper_case is greater than the number of upper case characters available to generate this password.")
        if min_digit > len(digits):
            raise ValueError(
                "digits can not be used more than once in a password and min_digit is greater than the number of digits available to generate this password.")
        if min_special > len(special):
            raise ValueError(
                "special characters can not be used more than once in a password and min_special is greater than the number of special characters available to generate this password.")

    generated_password = {}

    for group in char_groups:
        characters = group['characters']
        min_length = group['min']
        if min_length > 0 and len(characters) == 0:
            raise ValueError("No characters in '%s' can comply with the administrator password policy (min=%s)" % (
                characters, min_length))

        for _ in range(min_length):
            if len(generated_password) < length:
                index = str(randint())
                while index in generated_password:
                    index = str(randint())
                c = characters[randint() % len(characters)]
                generated_password[index] = c
                if prevent_repeating_chars:
                    characters = list(set(characters)-set(list(c)))
                    all_chars = list(set(all_chars)-set(list(c)))

    for _ in range(len(generated_password), length):
        index = str(randint())
        while index in generated_password:
            index = str(randint())
        c = all_chars[randint() % len(all_chars)]
        generated_password[index] = c
        if prevent_repeating_chars:
            all_chars = list(set(all_chars)-set(list(c)))

    return "".join(generated_password.values())


def main():
    # initialize
    module = AnsibleModule(
        argument_spec=dict(
            length=dict(type='int', default=12),
            min_upper_case=dict(type='int', default=2),
            min_lower_case=dict(type='int', default=2),
            min_digit=dict(type='int', default=2),
            min_special=dict(type='int', default=2),
            special_characters=dict(type='str', default=SPECIAL_CHARACTERS),
            forbidden_characters=dict(type='str'),
            prevent_repeating_characters=dict(type='bool', default=True)
        ),
        supports_check_mode=True,
    )

    params = {}

    if module.params['length']:
        length = module.params['length']
        if 1 > length or length > 128:
            module.fail_json(msg="valid length must be in range 1 - 128")
        params['length'] = length
        
    if module.params['min_upper_case']:
        params['min_upper_case'] = module.params['min_upper_case']
    if module.params['min_lower_case']:
        params['min_lower_case'] = module.params['min_lower_case']
    if module.params['min_digit']:
        params['min_digit'] = module.params['min_digit']
    if module.params['min_special']:
        params['min_special'] = module.params['min_special']
    if module.params['special_characters']:
        params['special_chars'] = module.params['special_characters']
    if module.params['forbidden_characters']:
        params['forbidden_chars'] = module.params['forbidden_characters']

    params['prevent_repeating_chars'] = module.params['prevent_repeating_characters']

    try:
        complex_password = mkpasswd(**params)
    except ValueError as e:
        module.fail_json(
            msg=to_text(e)
        )

    if module.check_mode:
        res_args = dict(ansible_facts=dict(complex_password=''), changed=False)
    else:
        res_args = dict(ansible_facts=dict(
            complex_password=complex_password), changed=True)

    module.exit_json(**res_args)


if __name__ == '__main__':
    main()
