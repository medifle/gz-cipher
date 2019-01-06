#!/usr/bin/env node

// encrypt directory?

const fs = require('fs')
const {Transform} = require('stream')
const zlib = require('zlib')
const crypto = require('crypto')

const version = '0.0.1'
let file // filepath
let passwd = Math.random().toString(36).substring(2)
let encryptFlag = 2 // 0: encrypt; 1: decrypt; 2: undefined


if (process.argv[2] === undefined) {
  throw Error('gz-cipher: No option specified')
} else if (process.argv[2] === '--help' || process.argv[2] === '-h') {
  console.log('  Usage:')
  console.log('  Encryption:'.padEnd(25) + 'gz-cipher -e file [-p password]')
  console.log('  Decryption:'.padEnd(25) +  'gz-cipher -d file')
  console.log('  -h, --help'.padEnd(25) + 'output usage information')
  console.log('  -v, --version'.padEnd(25) + 'output the version number')
} else if (process.argv[2] === '--version' || process.argv[2] === '-v') {
  console.log(version)
} else if (process.argv[2].substring(0, 1) === '-') {
  let options = process.argv[2].substring(1).split('')
  if (options.includes('e')) {
    if (!options.includes('d')) {
      encryptFlag = 0
    } else {
      encryptFlag = 2
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
      file = process.argv[3]
      if (encryptFlag === 0 && process.argv[4]) {
        if (process.argv[4].substring(0,2) === '-p') {
          if (process.argv[5] === undefined) {
            throw Error('gz-cipher: No password specified')
          } else if (process.argv[5].length < 8) {
            throw Error('gz-cipher: Password must contain at least 8 characters')
          } else {
            passwd = process.argv[5]
          }
        } else {
          throw Error('gz-cipher: Not a valid option')
        }
      }
    }
  }

}


console.log("file:",file)
console.log("passwd",passwd)

// if (!encryptFlag) {
//   process.exit()
// }

// const algo = 'aes192'
// const key = Buffer.concat([Buffer.from(passwd)], 24) // for aes192-cbc, key length is 192bits/8
// const iv = crypto.randomBytes(16) // for aes, iv length is 128bits/8

// const reportProgress = new Transform({
//   transform(chunk, encoding, callback) {
//     process.stdout.write('.')
//     callback(null, chunk)
//   }
// })

// if (encryptFlag) {
//   /* gzip and encrypt */
//   fs.createReadStream(file)
//     .pipe(zlib.createGzip()) // gzip
//     .pipe(crypto.createCipheriv(algo, key, iv)) // encrypt; key, iv are buffer here
//     .pipe(reportProgress)
//     .pipe(fs.createWriteStream(file + '.gz'))
//     .on('finish', () => console.log('Done'))
//     .on('close', () => {
//       fs.writeFile(
//         file + '_keys.json',
//         JSON.stringify({
//           algo,
//           key: key.toString('hex'),
//           iv: iv.toString('hex'),
//           passwd
//         }),
//         err => {
//           if (err) throw err
//           console.log(file + '_keys.json generated')
//         }
//       )
//       console.log(file + ' has been coded with: ')
//       console.log('key: ' + key.toString('hex'))
//       console.log('iv: ' + iv.toString('hex'))
//     })
// } else {
//   /* decrypt and gunzip, use the same ivstr when it was encrypted */
//   const keys = JSON.parse(
//     fs.readFileSync(file.slice(0, -3) + '_keys.json', 'utf8')
//   )
//   fs.createReadStream(file)
//     .pipe(
//       crypto.createDecipheriv(
//         keys.algo,
//         Buffer.from(keys.key, 'hex'),
//         Buffer.from(keys.iv, 'hex')
//       )
//     )
//     .pipe(zlib.createGunzip())
//     .pipe(reportProgress)
//     .pipe(fs.createWriteStream('decoded_' + file.slice(0, -3)))
//     .on('finish', () => console.log('Done'))
// }
