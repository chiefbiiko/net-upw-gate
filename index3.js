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

var TRUE_BUF = Buffer.from([ 0x01 ])

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
  opts.auth = opts.auth || true
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
        // indicate whether authentication is required for this server
        if (opts.auth) {
          socket.write(TRUE_BUF)
        } else {
          console.log('CRYPTO ONLY..!!!!')
          socket.removeListener('readable', readable)
          onauth(pumpify(encrypt, socket, decrypt))
        }
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
        })
        // decrypting the suspect
        decrypt.write(suspect)
        // once we got pubkey and upw forget the readable handler
        socket.removeListener('readable', readable)
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
  // callback counter
  var numReadables = 0
  // registering a one-time readable handler
  socket.on('readable', function onreadable () {
    ++numReadables
    if (numReadables === 1) {
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
      decrypt.setAutoPadding(false)
      socket = pumpify(encrypt, socket, decrypt)
      // // authentication
      // console.log('UPW', upw, upw.length)
      // socket.write(upw)
      console.log('LEFTOVA', socket.read(1))
    } else if (numReadables === 2) {
      // check whether server wants authentication
      var flag = socket.read(1)
      console.log('FLAG', flag)
      if (flag.equals(TRUE_BUF)) {
        // authentication
        console.log('UPW', upw, upw.length)
        socket.write(upw)
      } else {
        console.log('REMOVING ONREADABLE')
        socket.removeListener('readable', onreadable)
      }
    }
  })
}

module.exports = { createGate: netGate, clientEstablish: clientEstablish }
