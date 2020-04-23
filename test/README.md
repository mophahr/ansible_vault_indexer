# test vault directory

The vault password is "0000".

* `vault.yml` is an example vault file
* `vault__map.yml.reference` is how the mapping file created should look like
* `vault.yml.reference` is how the contents of `vault.yml` should look like after the script is executed

To test the script, run `./extract_keys.py -d test/ -p 0000 [-k]` and then compare the contents of the changed files with the reference files.
