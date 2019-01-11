# gz-cipher

`gz-cipher` is a command-line tool providing common ciphers to gzip and encrypt large files (or decrypt and gunzip) with low memory cost using Node built-in `stream`, `zlib` and `crypto` modules.

## Node version requirement

Please use `Node >= 10.0.0` for security reason

## Installation

Using npm:
```shell
$ npm i -g gz-cipher
```

## Usage

```
Encryption:            gz-cipher -e file [-a cipher] [-p password]
Decryption:            gz-cipher -d file
-h, --help             output usage information
-v, --version          output the version number
```

Currently supported ciphers: (see more on `openssl enc -help`)
```
aes-128-cbc
aes-192-cbc (default)
aes-256-cbc
aes-128-gcm
aes-192-gcm
aes-256-gcm
```

## Notes

`gz-cipher` won't overwrite your files if any output filename is conflict with your existing filename. Please rest assured :)

Directory encryption is not supported for now. However, if you zip the directory beforehand, `gz-cipher` still works

## Backstory

It was based on a practice when I was trying to implement a Transform `stream` and found it could be a handy tool to gzip and encrypt large files. Then I made it a CLI tool available on npm.

