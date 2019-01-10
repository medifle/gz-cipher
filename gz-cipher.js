#!/usr/bin/env node

//TODO: support other common ciphers

const fs = require('fs')
const path = require('path')
const {Transform} = require('stream')
const zlib = require('zlib')
const crypto = require('crypto')
const readline = require('readline')

const version = '1.0.0'
let filePathObj
let passwd = Math.random() // generate random password by default
  .toString(36)
  .substring(2)
let encryptFlag = 2 // 0: encrypt; 1: decrypt; 2: undefined

const usage = () => {
  console.log('Usage:')
  console.log('  Encryption:'.padEnd(25) + 'gz-cipher -e file [-p password]')
  console.log('  Decryption:'.padEnd(25) + 'gz-cipher -d file')
  console.log('  -h, --help'.padEnd(25) + 'output usage information')
  console.log('  -v, --version'.padEnd(25) + 'output the version number')
}

const writeWaitingPercent = p => {
  readline.clearLine(process.stdout, 0)
  readline.cursorTo(process.stdout, 0)
  process.stdout.write(`Waiting ... ${p}%`)
}

const cliParser = () => {
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
        console.error("gz-cipher: Can't specify both -e and -d")
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
      if (fileStats.isFile) {
        filePathObj = path.parse(process.argv[3])
        if (encryptFlag === 0 && process.argv[4]) {
          if (process.argv[4].substring(0, 2) === '-p') {
            if (process.argv[5] === undefined) {
              console.error('gz-cipher: No password specified')
              return
            } else if (process.argv[5].length < 8) {
              console.error(
                'gz-cipher: Password must contain at least 8 characters'
              )
              return
            } else {
              passwd = process.argv[5]
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
    const algo = 'aes192'
    const key = Buffer.concat([Buffer.from(passwd)], 24) // for aes192-cbc, key length is 192bits/8
    const iv = crypto.randomBytes(16) // for aes, iv length is 128bits/8

    let filepath = path.format(filePathObj)
    let stats = fs.statSync(filepath)
    let fileSizeInBytes = stats['size']
    let chunkLen = 0
    const reportProgress = new Transform({
      transform(chunk, encoding, callback) {
        chunkLen += chunk.length
        let percent = (chunkLen) / fileSizeInBytes * 100
        writeWaitingPercent(percent.toFixed(2))
        callback(null, chunk)
      }
    })

    /* gzip and encrypt */
    if (encryptFlag === 0) {
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
            .pipe(crypto.createCipheriv(algo, key, iv)) // encrypt; key, iv are buffer here
            .pipe(fs.createWriteStream(filepath + '.gz'))
            .on('finish', () => {
              console.log('\nDone')
            })
            .on('close', () => {
              fs.writeFile(
                keysPath,
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
                  console.log('iv: ' + iv.toString('hex') + '\n')
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
          .pipe(
            crypto.createDecipheriv(
              keys.algo,
              Buffer.from(keys.key, 'hex'),
              Buffer.from(keys.iv, 'hex')
            )
          )
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

cliParser()
