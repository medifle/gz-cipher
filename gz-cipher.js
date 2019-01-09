#!/usr/bin/env node

// what if keys.json is not there?
// encrypt directory? use archive module
// add as global shell command?

const fs = require('fs')
const path = require('path')
const {Transform} = require('stream')
const zlib = require('zlib')
const crypto = require('crypto')

const version = '1.0.0'
let filePathObj
let passwd = Math.random() // generate random password by default
  .toString(36)
  .substring(2)
let encryptFlag = 2 // 0: encrypt; 1: decrypt; 2: undefined

const usage = () => {
  console.log('  Usage:')
  console.log('  Encryption:'.padEnd(25) + 'gz-cipher -e file [-p password]')
  console.log('  Decryption:'.padEnd(25) + 'gz-cipher -d file')
  console.log('  -h, --help'.padEnd(25) + 'output usage information')
  console.log('  -v, --version'.padEnd(25) + 'output the version number')
}


if (process.argv[2] === undefined) {
  throw Error('gz-cipher: No option specified')
} else if (process.argv[2] === '--help' || process.argv[2] === '-h') {
  usage()
} else if (process.argv[2] === '--version' || process.argv[2] === '-v') {
  console.log(version)
} else if (process.argv[2].substring(0, 1) === '-') {
  let options = process.argv[2].substring(1).split('')
  if (options.includes('e')) {
    if (!options.includes('d')) {
      encryptFlag = 0
    } else {
      throw Error("gz-cipher: Can't specify both -e and -d")
    }
  } else if (options.includes('d')) {
    encryptFlag = 1
  } else {
    throw Error('gz-cipher: Not a valid option')
  }

  if (process.argv[3] === undefined) {
    throw Error('gz-cipher: No file specified')
  } else {
    let fileStats = fs.statSync(process.argv[3])
    if (fileStats.isFile) {
      filePathObj = path.parse(process.argv[3])
      if (encryptFlag === 0 && process.argv[4]) {
        if (process.argv[4].substring(0, 2) === '-p') {
          if (process.argv[5] === undefined) {
            throw Error('gz-cipher: No password specified')
          } else if (process.argv[5].length < 8) {
            throw Error(
              'gz-cipher: Password must contain at least 8 characters'
            )
          } else {
            passwd = process.argv[5]
          }
        } else {
          throw Error('gz-cipher: Not a valid option')
        }
      }
    }
  }
} else {
  usage()
}

if (encryptFlag !== 2 && filePathObj) {
  const algo = 'aes192'
  const key = Buffer.concat([Buffer.from(passwd)], 24) // for aes192-cbc, key length is 192bits/8
  const iv = crypto.randomBytes(16) // for aes, iv length is 128bits/8

  const reportProgress = new Transform({
    transform(chunk, encoding, callback) {
      process.stdout.write('.')
      callback(null, chunk)
    }
  })

  if (encryptFlag === 0) {
    /* gzip and encrypt */
    let filepath = path.format(filePathObj)
    fs.createReadStream(filepath)
      .pipe(zlib.createGzip()) // gzip
      .pipe(crypto.createCipheriv(algo, key, iv)) // encrypt; key, iv are buffer here
      .pipe(reportProgress)
      .pipe(fs.createWriteStream(filepath + '.gz'))
      .on('finish', () => {
        console.log('Done')
      })
      .on('close', () => {
        fs.writeFile(
          path.join(filePathObj.dir, `${filePathObj.name}.json`),
          JSON.stringify(
            {
              algo,
              key: key.toString('hex'),
              iv: iv.toString('hex'),
              passwd
            },
            null,
            2 // pretty json format
          ),
          err => {
            if (err) throw err
            console.log(`\n${filepath}.json was generated`)
            console.log(
              `Please keep the ${filePathObj.name}.json file in a private space`
            )
            console.log(
              `To decrypt, put the ${
                filePathObj.name
              }.json file under the same directory with the encrypted file`
            )
          }
        )
        console.log(`${filepath} has been encrypted into ${filepath}.gz with: `)
        console.log('key: ' + key.toString('hex'))
        console.log('iv: ' + iv.toString('hex'))
      })
  } else if (encryptFlag === 1) {
    let oriPathObj = {
      root: filePathObj.root,
      dir: filePathObj.dir,
      base: filePathObj.name,
      ext: path.extname(filePathObj.name),
      name: path.parse(filePathObj.name).name
    }

    /* decrypt and gunzip, use the same ivstr when it was encrypted */
    const keys = JSON.parse(
      fs.readFileSync(
        path.join(oriPathObj.dir, `${oriPathObj.name}.json`),
        'utf8'
      )
    )

    let decodedName = oriPathObj.name + '-decoded' + oriPathObj.ext
    console.log(decodedName) //test

    // TODO: check existence first
    fs.createReadStream(path.format(filePathObj))
      .pipe(
        crypto.createDecipheriv(
          keys.algo,
          Buffer.from(keys.key, 'hex'),
          Buffer.from(keys.iv, 'hex')
        )
      )
      .pipe(reportProgress)
      .pipe(zlib.createGunzip())
      .pipe(fs.createWriteStream(path.join(oriPathObj.dir, decodedName)))
      .on('finish', () => console.log('Done'))
      .on('close', () => {
        console.log(path.join(oriPathObj.dir, decodedName) + ' was generated')
      })
  }
}
