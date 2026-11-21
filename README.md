# bwclient
A simple rofi client for the bitwarden CLI

## Dependencies

### Compile-time dependencies
- CMake
- C11
- [bfutils](https://github.com/Exilio016/bfutils)

### Run-time dependencies
- rofi
- wl-copy
- jq
- keyctl

## Usage

- To create a new item in bitwarden, run `bwclient -c URL`. URL is a required argument. It will define the entry name.
- To edit an item, run `bwclient -e<URL>`. URL is an optional argument to filter the entries.
- To get the content of an item, run `bwclient -s<URL>`. URL is an optional argument to filter the entries.
