/*
  TODO:
    + encrypt the connection using ecdhe before exchanging any credentials !!!
*/

function isString (x) {
  return typeof x === 'string' || x instanceof String
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

function netGate (allow, opts, onauth) {
  if (typeof opts === 'function') {
    onauth = opts
    opts = {}
  }

  if (!allow || !onauth) throw Error('missing arguments')

  if (isString(allow) || Buffer.isBuffer(allow)) allow = JSON.parse(allow)
  if (!opts) opts = {}

  opts.maxTries = opts.maxTries || 3

  var invalids = {}
  var blacklist = []
  var allow = allow.map(function (hash) {
    return Buffer.isBuffer(hash) ? hash : Buffer.from(hash, 'hex')
  })

  function gate (socket) {
    var loc = where(socket)
    if (socket.bytesRead || blacklist.includes(loc)) return

    socket.once('readable', function () {
      var suspect = socket.read(64)  // expecting: sha512(user + ':' + password)
      if (!isValid(allow, suspect)) {
        if (invalids.hasOwnProperty(loc)) invalids[loc]++
        else invalids[loc] = 1
        if (invalids[loc] >= opts.maxTries) blacklist.push(loc)
      } else {
        onauth(socket)
      }
    })
  }

  return gate
}

module.exports = netGate
