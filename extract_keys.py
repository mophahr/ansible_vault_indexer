#!/usr/bin/env python

import os
import ansible
from argparse import ArgumentParser
from ansible.parsing.vault import VaultLib, VaultSecret
from ansible.module_utils._text import to_bytes, to_text
from ansible_vault import Vault
from getpass import getpass
import yaml
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

def get_decrypted_file_contents(file_name, vault):
    raw_data = vault.load_raw(open(file_name).read())
    return yaml.safe_load(raw_data)

def create_mapping_file(file_name, vault_data_structure):
    '''
    create a mapping file that contains the data structure found in the vault file
    and a mapping to the vault_ variable names
    '''
    with open(file_name[:-4] + "__map.yml", "w") as mapping_file:

        # write out the data structure found in the vault file:
        mapping_file.write("### data structure in {}:\n#\n".format(file_name.split("/")[-1]))
        print(yaml.dump(vault_data_structure).split("\n"))
        for struct_line in yaml.dump(vault_data_structure).split("\n")[:-1]:
            mapping_file.write("# {}\n".format(struct_line))

        # add the mappings `KEYNAME: "{{ vault_KEYNAME }}"` for all keys
        mapping_file.write("\n### mapping to vaulted_variables:\n")
        for key,_ in vault_data_structure.items():
            if not key.startswith("vault_"):
                mapping_file.write(yaml.dump({key: '{{ vault_' + key + ' }}'}))
            else:
                mapping_file.write(yaml.dump({key[6:]: '{{ ' + key + ' }}'}))

def add_vault_prefixes(vault_file_name, vault_password):
    '''
    add the prefix `vault_` to all top level variable names
    '''

    # matches any word that's not a comment and that doesn't start with `vault_`:
    top_level_variable_regex = re.compile('^(?!vault_)(\w+)')

    vault_key = VaultSecret(_bytes=to_bytes(vault_password))
    vault = VaultLib(secrets=[(vault_file_name, vault_key)])

    with open(vault_file_name, 'rb') as f:
        encrypted_bytes = f.read()

    decrypted_contents = to_text(vault.decrypt(encrypted_bytes, filename=vault_file_name))

    new_content_lines = []
    for line in decrypted_contents.split('\n'):
        new_content_lines.append(top_level_variable_regex.sub(r'vault_\1', line))

    with open(vault_file_name, 'wb') as f:
        f.write(vault.encrypt('\n'.join(new_content_lines), secret=vault_key, vault_id=vault_file_name))


def main():
    args = get_command_line_arguments()

    #see https://stackoverflow.com/a/43060743
    yaml.SafeLoader.add_constructor(u"!unsafe", unsafe_tag_constructor)

    vault = Vault(get_vault_password(args))

    for file_name in get_file_list(args.dir_name):
        print(file_name)
        # print("# data structure:\n")
        structure = get_structure(get_decrypted_file_contents(file_name,vault))

        create_mapping_file(file_name, structure)

        add_vault_prefixes(file_name, get_vault_password(args))

if __name__ == "__main__":
    main()
