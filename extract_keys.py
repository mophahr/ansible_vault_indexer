import os
import ansible
from argparse import ArgumentParser
from ansible_vault import Vault
from getpass import getpass
import yaml

class Unsafe(yaml.YAMLObject):
    yaml_tag = '!unsafe'

    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return 'Unsafe({})'.format(self.value)

    @classmethod
    def from_yaml(cls, loader, node):
        return Unsafe(node.value)

    @classmethod
    def to_yaml(cls, dumper, data):
        return dumper.represent_scalar(cls.yaml_tag, data.value)

# def unsafe_tag_constructor(loader, node):
#     # since we don't cate about the values here, all we need to return is some string
#     print(node)
#     return node.tag + " " + node.value

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
    list_of_files = list()
    for (dir_path, _, file_names) in os.walk(dir_name):
        list_of_files += [os.path.join(dir_path, file) for file in file_names if file.endswith(".yml") and not file.endswith("__map.yml")]
    return list_of_files

def get_vault_password(args):
    if args.ansible_vault_password is None:
        return(getpass("Ansible vault password: "))
    else:
        return(args.ansible_vault_password)

def get_structure(data):
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
    return yaml.load(raw_data)

def main():
    args = get_command_line_arguments()

    #see https://stackoverflow.com/a/43060743
    # yaml.SafeLoader.add_constructor(u"!unsafe", unsafe_tag_constructor)
    yaml.SafeLoader.add_constructor(u"!unsafe", Unsafe.from_yaml)
    yaml.SafeDumper.add_multi_representer(Unsafe, Unsafe.to_yaml)
    vault = Vault(get_vault_password(args))

    for file in get_file_list(args.dir_name):
        print(file)
        # print("# data structure:\n")
        structure = get_structure(get_decrypted_file_contents(file,vault))
        with open(file[:-4] + "__map.yml", "w") as outfile:
            yaml.safe_dump(get_decrypted_file_contents(file,vault), outfile)
            outfile.write("# data structure:\n")
            outfile.write(yaml.dump({"secret_structure__" + file.split("/")[-1][:-4]: structure}))
            outfile.write("# mapping to vaulted_variables:\n")
            for key,_ in structure.items():
                outfile.write(yaml.dump({key: '{{ vault_' + key + ' }}'}))
        outfile.close()
        yaml.safe_dump(get_decrypted_file_contents(file,vault))
        # print(yaml.dump({"secret_structure__" + file.split("/")[-1][:-4]: structure}))
        # print("# mapping to vaulted_variables:\n")
        # for key,_ in structure.items():
        #     print(yaml.dump({key: '{{ vault_' + key + ' }}'}))
        # print("\n\n")
        #vault.dump(data, open(file[:-4] + "__test.yml", "w"))
if __name__ == "__main__":
    main()
