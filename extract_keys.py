#!/usr/bin/env python

'''
extract_keys.py

Script to perform the following steps:

1.  Find all vault files (ending on .yml) in the file tree starting from `dir_name` [default: "./"]
2.  Open all of them and extract their structure.
    The script assumes that only the leaeves at the lowest level are secret, i.e., something like:

        non_secret_key_level_1:
          non-secret_key_level_2:
            secret_value

3.  Write everything but the secret value into a newly created file in the same folder as the vault file.
    This new file gets the `__map` prefix
4.  In the new file create a mapping `non_secret_key_level_1: "{{ vault_non_secret_key_level_1 }}"`
5.  In the vault file, add the prefix `vault_` to the original name of all top-level keys unless they are already prefixed as such.
    This can be turned off using the flag "--keep_vault_files".

EXAMPLE USAGE:

    ./extract_keys.py -d test/ -p 0000
'''


import os
import ansible
from argparse import ArgumentParser
from ansible.parsing.vault import VaultLib, VaultSecret
from ansible.module_utils._text import to_bytes, to_text
from getpass import getpass
import yaml
import sys
import re

def unsafe_tag_constructor(loader, node):
    '''
    This constructor is needed to avoid errors caused by the `!unsafe` tag
    Since we don't care about the values here, all we need to return is some string
    '''
    return "unsafe tag string"

def get_command_line_arguments():
    parser = ArgumentParser()
    parser.add_argument("-d", "--directory",
                            dest="dir_name",
                            help="directory to start from [default: './']",
                            default="./")
    parser.add_argument("-p", "--ansible_vault_password",
                            dest="ansible_vault_password",
                            help="vault password")
    parser.add_argument("-k", "--keep_vault_files",
                            dest="keep_vault_files",
                            default=False,
                            help="use this flag to stop the script from altering the original vault files",
                            action="store_true")
    return parser.parse_args()

def get_file_list(dir_name):
    '''
    return all files in the directory tree that end on ".yml" but exclude files ending on "__map.yml"
    '''
    list_of_files = list()
    for (dir_path, _, file_names) in os.walk(dir_name):
        list_of_files += [os.path.join(dir_path, file) for file in file_names if file.endswith(".yml") and not file.endswith("__map.yml")]
    return list_of_files

def get_vault_password(args):
    '''
    return the vault password
    '''
    if args.ansible_vault_password is None:
        return(getpass("Ansible vault password: "))
    else:
        return(args.ansible_vault_password)

def get_structure(data):
    '''
    return the structure of `data`, i.e. all the keys but none of the values
    '''
    if type(data) == list:
        keys = []
        for list_element in data:
            keys += [get_structure(list_element)]
        return keys
    elif type(data) == dict:
        keys = {}
        for key, value in data.items():
            if type(data[key]) != dict and type(data[key]) != list:
                keys.update({key:"secret"})
            else:
                keys.update({key:get_structure(value)})
        return keys

def get_decrypted_file_contents(vault_file_name, vault_password):
    '''
    return a yaml dictionary of the vault_contents
    '''
    _, _, text_contents = open_vault(vault_file_name, vault_password)

    if len(text_contents) <= 1:
        return yaml.safe_load("{}")
    else:
        return yaml.safe_load(text_contents)

def create_mapping_file(file_name, vault_data_structure):
    '''
    create a mapping file that contains the data structure found in the vault file
    and a mapping to the vault_ variable names
    '''
    with open(file_name[:-4] + "__map.yml", "w") as mapping_file:

        # write out the data structure found in the vault file:
        mapping_file.write("### data structure in {}:\n#\n".format(file_name.split("/")[-1]))

        for struct_line in yaml.dump(vault_data_structure).split("\n")[:-1]:
            mapping_file.write("# {}\n".format(struct_line))

        # add the mappings `KEYNAME: "{{ vault_KEYNAME }}"` for all keys
        mapping_file.write("\n### mapping to vaulted_variables:\n")
        for key,_ in vault_data_structure.items():
            if not key.startswith("vault_"):
                mapping_file.write(yaml.dump({key: "{{ vault_" + key + " }}"}))
            else:
                mapping_file.write(yaml.dump({key[6:]: "{{ " + key + " }}"}))

def open_vault(vault_file_name, vault_password):
    '''
    return decrypted contents of a vault (and teh vault itself)
    '''
    vault_key = VaultSecret(_bytes=to_bytes(vault_password))
    vault = VaultLib(secrets=[(vault_file_name, vault_key)])

    with open(vault_file_name, "rb") as f:
        encrypted_bytes = f.read()

    return vault, vault_key, to_text(vault.decrypt(encrypted_bytes, filename=vault_file_name))

def add_vault_prefixes(vault_file_name, vault_password):
    '''
    add the prefix `vault_` to all top level variable names
    '''

    # matches any word that's not a comment and that doesn't start with `vault_`:
    top_level_variable_regex = re.compile("^(?!vault_)(\w+)")

    vault, vault_key, decrypted_contents = open_vault(vault_file_name, vault_password)

    new_content_lines = []
    for line in decrypted_contents.split("\n"):
        new_content_lines.append(top_level_variable_regex.sub(r"vault_\1", line))

    with open(vault_file_name, "wb") as f:
        f.write(vault.encrypt("\n".join(new_content_lines), secret=vault_key, vault_id=vault_file_name.split("/")[-2]))

def get_python_version():
    if sys.version_info >= (3, 0):
        return 3
    else:
        return 2

def main():
    args = get_command_line_arguments()

    if not get_python_version() == 3:
        print("please use Python 3")
        return 1


    #see https://stackoverflow.com/a/43060743
    yaml.SafeLoader.add_constructor(u"!unsafe", unsafe_tag_constructor)

    ansible_vault_password = get_vault_password(args)

    for file_name in get_file_list(args.dir_name):
        structure = get_structure(get_decrypted_file_contents(file_name, ansible_vault_password))

        print("saving structure and mapping of {}".format(file_name))
        create_mapping_file(file_name, structure)

        if not args.keep_vault_files:
            print("replacing top-level key names in the original vault file {}".format(file_name))
            add_vault_prefixes(file_name, ansible_vault_password)
        else:
            print("keeping original vault file {}".format(file_name))

if __name__ == "__main__":
    main()
