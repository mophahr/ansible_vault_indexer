# ansible vault indexer

Python script to decrypt Ansible vault files and add a plain-text mapping for better searchability.

## usage

```
extract_keys.py [-h] [-d DIR_NAME] [-p ANSIBLE_VAULT_PASSWORD] [-k]

optional arguments:
  -h, --help            show this help message and exit
  -d DIR_NAME, --directory DIR_NAME
                        directory to start from [default: './']
  -p ANSIBLE_VAULT_PASSWORD, --ansible_vault_password ANSIBLE_VAULT_PASSWORD
                        vault password
  -k, --keep_vault_files
                        use this flag to stop the script from altering the
                        original vault files
```

## `test` folder

This folder is an example directory for testing the script
