#!/usr/bin/env node

const version = '1.1.0'
const fs = require('fs')
const path = require('path')
const {Transform} = require('stream')
const zlib = require('zlib')
const crypto = require('crypto')
const readline = require('readline')
let filePathObj
const algoSupported = [
  'aes-128-cbc',
  'aes-192-cbc',
  'aes-256-cbc',
  'aes-128-gcm',
  'aes-192-gcm',
  'aes-256-gcm'
]
let algo = algoSupported[1] // default algorithm, see more on `openssl list-cipher-algorithms`
// generate random password by default
let passwd = crypto.randomBytes(32).toString('hex')
let encryptFlag = 2 // 0: encrypt; 1: decrypt; 2: undefined

const usage = () => {
  console.log('Usage:')
  console.log(
    '  Encryption:'.padEnd(25) + 'gz-cipher -e file [-a cipher] [-p password]'
  )
  console.log('  Decryption:'.padEnd(25) + 'gz-cipher -d file')
  console.log('  -h, --help'.padEnd(25) + 'output usage information')
  console.log('  -v, --version'.padEnd(25) + 'output the version number')
}

const setPasswd = i => {
  let arg = process.argv[i]
  if (arg === undefined) {
    throw Error('gz-cipher: No password specified')
  } else if (arg.length < 8) {
    throw Error('gz-cipher: Password must contain at least 8 characters')
  } else {
    passwd = arg
  }
}

const setCipher = i => {
  let arg = process.argv[i]
  if (arg === undefined) {
    throw Error('gz-cipher: No cipher specified')
  } else if (!algoSupported.includes(arg)) {
    throw Error('gz-cipher: Not a supported cipher')
  } else {
    algo = arg
  }
}

const writeWaitingPercent = p => {
  readline.clearLine(process.stdout, 0)
  readline.cursorTo(process.stdout, 0)
  process.stdout.write(`Waiting ... ${p}%`)
}

const main = () => {
  if (process.argv[2] === undefined) {
    console.error('gz-cipher: No option specified')
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
        console.error("gz-cipher: Can't specify both -e and -d options")
      }
    } else if (options.includes('d')) {
      encryptFlag = 1
    } else {
      console.error('gz-cipher: Not a valid option')
    }

    if (process.argv[3] === undefined) {
      console.error('gz-cipher: No file specified')
      return
    } else {
      let fileStats = fs.statSync(process.argv[3])
      if (fileStats.isDirectory()) {
        console.error(`${process.argv[3]} is a directory, please zip it first`)
      }
      if (!fileStats.isDirectory() && fileStats.isFile()) {
        filePathObj = path.parse(process.argv[3])
        if (encryptFlag === 0 && process.argv[4]) {
          if (process.argv[4].substring(0, 2) === '-a') {
            try {
              setCipher(5)
            } catch (error) {
              console.error(`${error}`)
              return
            }
            if (process.argv[6]) {
              if (process.argv[6].substring(0, 2) === '-p') {
                try {
                  setPasswd(7)
                } catch (error) {
                  console.error(`${error}`)
                  return
                }
              } else {
                console.error('gz-cipher: Not a valid option')
                return
              }
            }
          } else if (process.argv[4].substring(0, 2) === '-p') {
            try {
              setPasswd(5)
            } catch (error) {
              console.error(`${error}`)
              return
            }
          } else {
            console.error('gz-cipher: Not a valid option')
            return
          }
        }
      }
    }
  } else {
    usage()
  }

  if (encryptFlag !== 2 && filePathObj) {
    let filepath = path.format(filePathObj)
    let stats = fs.statSync(filepath)
    let fileSizeInBytes = stats['size']
    let chunkLen = 0
    const reportProgress = new Transform({
      transform(chunk, encoding, callback) {
        chunkLen += chunk.length
        let percent = (chunkLen / fileSizeInBytes) * 100
        writeWaitingPercent(percent.toFixed(2))
        callback(null, chunk)
      }
    })

    /* gzip and encrypt */
    if (encryptFlag === 0) {
      let keylen = 24 // for aes192-cbc, key length is 192bits/8
      let ivLen = 16 // for AES CBC, iv length is 128bits/8
      let cipherOption = null

      if (algo !== 'aes-192-cbc') {
        if (algo === 'aes-256-cbc') {
          keylen = 32
        } else if (algo === 'aes-128-cbc') {
          keylen = 16
        } else if (algo === 'aes-256-gcm') {
          keylen = 32
          ivLen = 12
          // cipherOption = {authTagLength: 16}  // default for GCM is 16
        } else if (algo === 'aes-192-gcm') {
          keylen = 24
          ivLen = 12
        } else if (algo === 'aes-128-gcm') {
          keylen = 16
          ivLen = 12
        }
      }

      const iv = crypto.randomBytes(ivLen)
      const salt = crypto.randomBytes(16)
      const key = crypto.pbkdf2Sync(passwd, salt, 1000000, keylen, 'sha512')
      const cipher = crypto.createCipheriv(algo, key, iv, cipherOption)

      fs.open(`${filepath}.gz`, 'wx', (err, fd) => {
        if (err) {
          if (err.code === 'EEXIST') {
            console.error(`${filepath}.gz already exists`)
            return
          }
          throw err
        }
        let keysPath = path.join(filePathObj.dir, `${filePathObj.name}.json`)
        fs.open(keysPath, 'wx', (err, fd) => {
          if (err) {
            if (err.code === 'EEXIST') {
              console.error(`${keysPath} already exists`)
              fs.unlinkSync(`${filepath}.gz`)
              return
            }
            throw err
          }
          fs.createReadStream(filepath)
            .pipe(reportProgress)
            .pipe(zlib.createGzip()) // gzip
            .pipe(cipher) // encrypt; key, iv are buffer here
            .pipe(fs.createWriteStream(filepath + '.gz'))
            .on('finish', () => {
              console.log('\nDone')
            })
            .on('close', () => {
              let tag = null
              if (algo.indexOf('gcm') !== -1) {
                tag = cipher.getAuthTag().toString('hex')
              }
              fs.writeFile(
                keysPath,
                JSON.stringify(
                  {
                    algo,
                    key: key.toString('hex'),
                    iv: iv.toString('hex'),
                    passwd,
                    tag
                  },
                  null,
                  2 // pretty json format
                ),
                err => {
                  if (err) throw err
                  console.log(`\n${filepath}.json was generated`)
                  console.log(
                    `Please keep the ${
                      filePathObj.name
                    }.json file in a private space`
                  )
                  console.log(
                    `To decrypt, put the ${
                      filePathObj.name
                    }.json file under the same directory with the encrypted file\n`
                  )
                  console.log(
                    `${filepath} has been encrypted into ${filepath}.gz with: `
                  )
                  console.log('key: ' + key.toString('hex'))
                  console.log('iv: ' + iv.toString('hex'))
                  console.log(
                    'tag: ' + (tag ? tag.toString('hex') : null) + '\n'
                  )
                }
              )
            })
        })
      })
    } else if (encryptFlag === 1) {
      /* decrypt and gunzip, use the same ivstr when it was encrypted */
      let oriPathObj = {
        root: filePathObj.root,
        dir: filePathObj.dir,
        base: filePathObj.name,
        ext: path.extname(filePathObj.name),
        name: path.parse(filePathObj.name).name
      }

      const keys = JSON.parse(
        fs.readFileSync(
          path.join(oriPathObj.dir, `${oriPathObj.name}.json`),
          'utf8'
        )
      )
      const decipher = crypto.createDecipheriv(
        keys.algo,
        Buffer.from(keys.key, 'hex'),
        Buffer.from(keys.iv, 'hex')
      )
      if (keys.tag) {
        decipher.setAuthTag(Buffer.from(keys.tag, 'hex'))
      }

      let decodedName = oriPathObj.name + '-decoded' + oriPathObj.ext
      let writePath = path.join(oriPathObj.dir, decodedName)
      fs.open(`${writePath}`, 'wx', (err, fd) => {
        if (err) {
          if (err.code === 'EEXIST') {
            console.error(`${writePath} already exists`)
            return
          }
          throw err
        }
        fs.createReadStream(path.format(filePathObj))
          .pipe(reportProgress)
          .pipe(decipher)
          .pipe(zlib.createGunzip())
          .on('error', err => {
            process.stdout.write('Hello, World')
            process.stdout.clearLine()
            process.stdout.cursorTo(0)
            fs.unlinkSync(`${writePath}`)
            throw err
          })
          .pipe(fs.createWriteStream(writePath))
          .on('finish', () => console.log('\nDone'))
          .on('close', () => {
            console.log(`${writePath} was generated\n`)
          })
      })
    }
  }
}

main()
