# complex_password - Creates a random and complex password with rules

## Synopsis

* Ansible module to randomly generate a complex and strong password that match sets of rules.

## Parameters

| Parameter     | Choices/<font color="blue">Defaults</font> | Comments |
| ------------- | ---------|--------- |
|__length__<br><font color="purple">integer</font></font> / <font color="red">No</font> | __Default:__<br><font color="blue">12</font> | The number of characters in the generated password.<br>The length must be between `1` and `128` characters. |
|__min_upper_case__<br><font color="purple">integer</font></font> / <font color="red">No</font> | __Default:__<br><font color="blue">2</font> | The minimum number of uppercase letters of European languages (`A` through `Z`) in the newly generated password.<br>To exclude upper case characters from the password, specify `-1`. |
|__min_lower_case__<br><font color="purple">integer</font></font> / <font color="red">No</font> | __Default:__<br><font color="blue">2</font> | The minimum number of lowercase letters of European languages (`a` through `z`) in the newly generated password.<br>To exclude lower case characters from the password, specify `-1`. |
|__min_digit__<br><font color="purple">integer</font></font> / <font color="red">No</font> | __Default:__<br><font color="blue">2</font> | The minimum number of characters from base 10 digits (`0` through `9`) in the newly generated password.<br>To exclude digits from the password, specify `-1`. |
|__min_special__<br><font color="purple">integer</font></font> / <font color="red">No</font> | __Default:__<br><font color="blue">2</font> | The minimum number of non-alphanumeric characters (special characters) in the newly generated password.<br>To exclude special characters from the password, specify `-1`. |
|__special_characters__<br><font color="purple">string</font></font> / <font color="red">No</font> | __Default:__<br><font color="blue">/*!\\"$%()=?{[]}+\#-.,<'_:;>~\|@</font> | A string containing all special characters allowed to use. |
|__forbidden_characters__<br><font color="purple">string</font></font> / <font color="red">No</font> |  | The characters that cannot be used when generating a new password, e.g `/~\`. |
|__prevent_repeating_characters__<br><font color="purple">boolean</font></font> / <font color="red">No</font> | __Choices__: <ul><li>no</li><li><font color="blue">__yes &#x2190;__</font></li></ul> | Whether or not characters can be used more than once in a password. |

## Examples

```yaml
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

```

## Return Values

Facts returned by this module are added/updated in the `hostvars` host facts and can be referenced by name just like any other host fact. They do not need to be registered in order to use them.

| Fact   | Returned   | Description |
| ------ |------------| ------------|
|__complex_password__<br><font color="purple">string</font> | success | A string containing the password in plain text. |

## Authors

* Stéphane Bilqué (@sbilque)

## License

This project is licensed under the Apache 2.0 License.

See [LICENSE](LICENSE) to see the full text.
