/* generate a big file for test */
// const fs = require('fs')
// const file = fs.createWriteStream('./big.file')
// for (let i = 0; i < 1E6; i++) {
//   file.write('Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.\n')
// }
// file.end()

const fs = require('fs')
const {Transform} = require('stream')
const zlib = require('zlib')
const crypto = require('crypto')

const algo = 'aes192'
const file = process.argv[2]
const passwd = process.argv[3] || 'a_secret'
const key = Buffer.concat([Buffer.from(passwd)], 24) // for aes192-cbc, key length is 192bits/8
const iv = crypto.randomBytes(16) // for aes, iv length is 128bits/8

const reportProgress = new Transform({
  transform(chunk, encoding, callback) {
    process.stdout.write('.')
    callback(null, chunk)
  }
})

/* gzip and encrypt */
// fs.createReadStream(file)
//   .pipe(zlib.createGzip()) // gzip
//   .pipe(crypto.createCipheriv(algo, key, iv)) // encrypt; key, iv are buffer here
//   .pipe(reportProgress)
//   .pipe(fs.createWriteStream(file + '.gz'))
//   .on('finish', () => console.log('Done'))
//   .on('close', () => {
//     fs.writeFile(
//       file + '_keys.json',
//       JSON.stringify({algo, key: key.toString('hex'), iv: iv.toString('hex'), passwd}),
//       err => {
//         if (err) throw err
//         console.log(file + '_keys.json generated')
//       }
//     )
//     console.log(file + ' has been coded with: ')
//     console.log('key: ' + key.toString('hex'))
//     console.log('iv: ' + iv.toString('hex'))
//   })

/* decrypt and gunzip, use the same ivstr when it was encrypted */
const keys = JSON.parse(
  fs.readFileSync(file.slice(0, -3) + '_keys.json', 'utf8')
)
fs.createReadStream(file)
  .pipe(
    crypto.createDecipheriv(
      keys.algo,
      Buffer.from(keys.key, 'hex'),
      Buffer.from(keys.iv, 'hex')
    )
  )
  .pipe(zlib.createGunzip())
  .pipe(reportProgress)
  .pipe(fs.createWriteStream('decoded_' + file.slice(0, -3)))
  .on('finish', () => console.log('Done'))
