/*
  TODO:
    + encrypt the connection using ecdhe before exchanging any credentials !!!
    + move from elliptic to builtin crypto ECDH
*/

var crypto = require('crypto')
var net = require('net')
var pumpify = require('pumpify')
var EC = require('elliptic').ec

var ec = new EC('curve25519')

function sha512 (buf) {
  return crypto.createHash('sha512').update(buf).digest()
}

function where (socket) {
  return socket.remoteAddress + ':' + socket.remotePort
}

function isValid (allow, suspect) {
  suspect = Buffer.isBuffer(suspect) ? suspect : Buffer.from(suspect, 'hex')
  return allow.some(function (hash) {
    return hash.equals(suspect)
  })
}

/*
  opts.cipherAlgorithm: string = aes192
  opts.maxTries: number = 3
*/
function netGate (allow, opts, onauth) {
  if (typeof opts === 'function') {
    onauth = opts
    opts = {}
  }

  if (!allow || !onauth) throw Error('missing arguments')

  if (!Array.isArray(allow)) allow = JSON.parse(allow)
  if (!opts) opts = {}

  opts.maxTries = opts.maxTries || 3
  opts.cipherAlgorithm = opts.cipherAlgorithm || 'aes256'

  var invalids = {}
  var blacklist = []
  var allow = allow.map(function (hash) {
    return Buffer.isBuffer(hash) ? hash : Buffer.from(hash, 'hex')
  })

  function gate (socket) {
    var loc = where(socket)
    if (socket.bytesRead || blacklist.includes(loc)) return

    var keypair = ec.genKeyPair()
    var pubkey = Buffer.from(keypair.getPublic('binary'))
    var encrypt
    var decrypt
    var nonce
    var upw = Buffer.alloc(0)

    var numReadables = 0

    socket.on('readable', function readable () {
      // callback counter
      ++numReadables
      if (numReadables === 1) {
        // sending server's pubkey
        socket.write(pubkey)
        // gettin client's pubkey
        var otherPubkey = socket.read(32)
        // computing the shared secret
        var shared = keypair.derive(ec.keyFromPublic(otherPubkey).getPublic())
        // hashing the shared secret to a nonce 4 use with symmetric encryption
        nonce = sha512(shared.toString(16))
console.log('SERVER NONCE', nonce)
        // binding en/decryption to the socket
        encrypt = crypto.createCipher(opts.cipherAlgorithm, nonce)
        decrypt = crypto.createDecipher(opts.cipherAlgorithm, nonce)
        // socket = pumpify(encrypt, socket, decrypt)

      } else if (numReadables === 2) {
        // expecting: sha512(user + ':' + password)
        var suspect = socket.read(64)
console.log('SUSPECT', suspect, suspect.length)
        var decrypt2 = crypto.createDecipher(opts.cipherAlgorithm, nonce)
        decrypt2.setAutoPadding(false)



        decrypt2.on('data', function (chunk) {
console.log('CHUNK', chunk, chunk.length)
          upw = Buffer.concat([ upw, chunk ])
        })

        decrypt2.on('end', function () {
console.log('DECRYPTED UPW', upw, upw.length)
          if (!isValid(allow, upw)) {
            if (invalids.hasOwnProperty(loc)) invalids[loc]++
            else invalids[loc] = 1
            if (invalids[loc] >= opts.maxTries) blacklist.push(loc)
          } else {
console.log('AUTHENTICATED!!!!!!!')
            onauth(pumpify(encrypt, socket, decrypt))
          }

          // once we got pubkey and upw forget this handler
          socket.removeListener('readable', readable)
        })

        decrypt2.write(suspect)
        decrypt2.end()

      }

     // now only left with getting auth data thru



    })

    // socket.once('readable', function () {
    //
    //   var suspect = socket.read(64)  // expecting: sha512(user + ':' + password)
    //
    //
    //
    //   if (!isValid(allow, suspect)) {
    //     if (invalids.hasOwnProperty(loc)) invalids[loc]++
    //     else invalids[loc] = 1
    //     if (invalids[loc] >= opts.maxTries) blacklist.push(loc)
    //   } else {
    //     onauth(socket)
    //   }
    // })
  }

  return gate
}

function clientEstablish (socket, upw, opts) {
  if (!opts) opts = {}
  opts.cipherAlgorithm = opts.cipherAlgorithm || 'aes256'
  // ECDHE keys
  var keypair = ec.genKeyPair()
  var pubkey = Buffer.from(keypair.getPublic('binary'))
  // sending clilent's pubkey
  socket.write(pubkey)
  // gettin servert's pubkey
  socket.once('readable', function () {
    var otherPubkey = socket.read(32)
    // computing the shared secret
    var shared = keypair.derive(ec.keyFromPublic(otherPubkey).getPublic())
    // hashing the shared secret to a nonce 4 use with symmetric encryption
    var nonce = sha512(shared.toString(16))
console.log('CLIENT NONCE', nonce)
    // binding en/decryption to the socket
    var encrypt = crypto.createCipher(opts.cipherAlgorithm, nonce)
    var decrypt = crypto.createDecipher(opts.cipherAlgorithm, nonce)
    socket = pumpify(encrypt, socket, decrypt)
    // authentication
console.log('UPW', upw, upw.length)
    socket.write(upw)
  })
}

module.exports = { createGate: netGate, clientEstablish: clientEstablish }
