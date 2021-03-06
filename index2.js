/*
  TODO:
    + make auth optional
    + get rid of stream.push() after EOF error
*/

var crypto = require('crypto')
var net = require('net')
var pumpify = require('pumpify')
var EC = require('elliptic').ec

var ec = new EC('curve25519')

function sha512 (buf) {
  return crypto.createHash('sha512').update(buf).digest()
}

function isValid (allow, suspect) {
  suspect = Buffer.isBuffer(suspect) ? suspect : Buffer.from(suspect, 'hex')
  return allow.some(function (hash) {
    return hash.equals(suspect)
  })
}

/*
  opts.auth: boolean = false
  opts.cipherAlgorithm: string = 'aes256'
  opts.maxTries: number = 3
*/
function netGate (allow, opts, onauth) {
  if (typeof opts === 'function') {
    onauth = opts
    opts = {}
  }

  if (!onauth) throw Error('callback is not a function')

  // default options
  if (!opts) opts = {}
  opts.auth = opts.auth || false
  opts.maxTries = opts.maxTries || 3
  opts.cipherAlgorithm = opts.cipherAlgorithm || 'aes256'

  if (opts.auth && !allow) throw Error('missing argument "allow"')

  // more closure captures
  var invalids = {}
  var blacklist = []

  // making sure allow is an Buffer[]
  if (!Array.isArray(allow)) allow = JSON.parse(allow)
  allow = allow.map(function (hash) {
    return Buffer.isBuffer(hash) ? hash : Buffer.from(hash, 'hex')
  })

  function gate (socket) {
    // getting the soocket's remote address
    var addy = socket.remoteAddress + ':' + socket.remotePort
    if (socket.bytesRead || blacklist.includes(addy)) return

    // crypto setup
    var keypair = ec.genKeyPair()
    var pubkey = Buffer.from(keypair.getPublic('binary'))
    var encrypt
    var decrypt
    var nonce

    // callback counter
    var numReadables = 0

    socket.on('readable', function readable () {
      ++numReadables
      if (numReadables === 1) { // case encryption
        // sending server's pubkey
        socket.write(pubkey)
        // getting client's pubkey
        var otherPubkey = socket.read(32)
        // computing the shared secret
        var shared = keypair.derive(ec.keyFromPublic(otherPubkey).getPublic())
        // hashing the shared secret to a nonce 4 use with symmetric encryption
        nonce = sha512(shared.toString(16))
        console.log('SERVER NONCE', nonce)
        // initialising en/decryption streams with our shared nonce
        encrypt = crypto.createCipher(opts.cipherAlgorithm, nonce)
        decrypt = crypto.createDecipher(opts.cipherAlgorithm, nonce)
        decrypt.setAutoPadding(false)
      } else if (numReadables === 2) { // case authentication
        // expecting: sha512(user + ':' + password)
        var suspect = socket.read(64)
        console.log('SUSPECT', suspect, suspect.length)
        // registering a one-time data handler
        decrypt.once('data', function (chunk) {
          console.log('CHUNK', chunk, chunk.length)
          // check for authentication
          if (!isValid(allow, chunk)) {
            // store invalid authentication requests for this addy
            if (invalids.hasOwnProperty(addy)) invalids[addy]++
            else invalids[addy] = 1
            if (invalids[addy] >= opts.maxTries) blacklist.push(addy)
          } else {
            // allow the connection
            console.log('AUTHENTICATED!!!!!!!')
            onauth(pumpify(encrypt, socket, decrypt))
          }
          // once we got pubkey and upw forget the readable handler
          socket.removeListener('readable', readable)
        })
        decrypt.write(suspect)
      }
    })

  }

  return gate
}

function clientEstablish (socket, upw, opts) {
  // options
  if (!opts) opts = {}
  opts.cipherAlgorithm = opts.cipherAlgorithm || 'aes256'
  // ECDHE keys
  var keypair = ec.genKeyPair()
  var pubkey = Buffer.from(keypair.getPublic('binary'))
  // sending client's pubkey
  socket.write(pubkey)
  // registering a one-time readable handler
  socket.once('readable', function () {
    // getting the server's pubkey
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
