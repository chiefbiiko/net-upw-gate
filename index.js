var fs = require('fs')

function isString (x) {
  return typeof x === 'string' || x instanceof String
}

function where (socket) {
  return socket.remoteAddress + ':' + socket.remotePort
}

function isValid (allow, suspect) {
  console.log('ALLOW', allow)
  suspect = isString(suspect) ? Buffer.from(suspect, 'hex') : suspect
  return allow.some(function (hash) {
    hash = isString(hash) ? Buffer.from(hash, 'hex') : hash
    return hash.equals(suspect)
  })
}

// allow: String | Buffer | String[]
//   schema:: [ sha512(user + ':' + password), ... ]
// onauth: Function
// opts.that: this
// opts.maxTries: 3
function makeGate (allow, opts, onauth) {
  if (typeof opts === 'function') {
    onauth = opts
    opts = {}
  }

  if (!allow || !onauth) throw Error('allow \'am')
console.log('ALLOW', allow)
  if (isString(allow) || Buffer.isBuffer(allow)) allow = JSON.parse(allow)
  if (!opts) opts = {}
  var invalids = {}
  var blacklist = []

  // designed to be the very first connection handler of a net.Server instance
  // onauth(socket) callback is only called if the socket could be authenticated
  function gate (socket) {
    if (socket.bytesRead) return

    var loc = where(socket)
    if (blacklist.includes(loc)) return

    var suspect = socket.read(64)  // expecting: sha512(user + ':' + password)
console.log('ALLOW', allow)
    if (!isValid(allow, suspect)) {
      if (invalids.hasOwnProperty(loc)) invalids[loc]++
      else invalids[loc] = 1
      if (invalids[loc] >= opts.maxTries) blacklist.push(loc)
      return
    }
    return onauth.call(this, socket)
  }

  return gate
}

module.exports = makeGate
