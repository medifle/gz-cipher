# gz-cipher

`gz-cipher` is a command-line tool providing common ciphers to gzip and encrypt large files(or gunzip and decrypt) with low memory cost using Node built-in `stream`, `zlib` and `crypto` modules.

Using npm:
```shell
$ npm i -g gz-cipher
```

Usage
```
  Encryption:            gz-cipher -e file [-p password]
  Decryption:            gz-cipher -d file
  -h, --help             output usage information
  -v, --version          output the version number
```

## Notes

`gz-cipher` won't overwritten your files if any output filename is conflict with your existing filename. Rest assured :)

Currently only support cipher is `aes-192-cbc`


## Backstory

It is based on a practice when I was trying to implement a Transform `stream` and found it could be a handy tool to gzip and encrypt large files. Then I made it a CLI tool available on npm.

