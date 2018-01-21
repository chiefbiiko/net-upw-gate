var fs = require('fs')

// forget the type def, just make it a closure factory
// and no public blacklisting either that is controlled at init

function isString (x) {
  return typeof x === 'string' || x instanceof String
}

function where (socket) {
  return socket.remoteAddress + ':' + socket.remotePort
}

// allow: String | Buffer | String[]
//   schema:: [ sha512(user + ':' + password), ... ]
// onauth: Function
// opts.that: this
// opts.maxTries: 3
function NetGate (allow, opts, onauth) {
  if (!(this instanceof NetGate)) return new NetGate(allow, opts, onauth)

  if (typeof opts === 'function') {
    onauth = opts
    opts = {}
  }

  if (!allow || !onauth) throw Error('allow \'am')

  if (isString(allow) || Buffer.isBuffer(allow)) allow = JSON.parse(allow)
  if (!opts) opts = {}

  this._opts = opts
  this._onauth = onauth
  this._invalids = {}
  this._blacklist = []
  this._allow = allow.map(function (hash) {
    return Buffer.isBuffer(hash) ? hash : Buffer.from(hash, 'hex')
  })

}

NetGate.prototype._isValid = function isValid (suspect) {
  suspect = Buffer.isBuffer(suspect) ? suspect : Buffer.from(suspect, 'hex')
  return this._allow.some(function (hash) {
    return hash.equals(suspect)
  })
}

// designed to be the very first connection handler of a net.Server instance
// onauth(socket) callback is only called if the socket could be authenticated
NetGate.prototype.protect = function protect (socket) {
    var loc = where(socket)

    if (socket.bytesRead || this._blacklist.includes(loc)) return

    var suspect = socket.read(64)  // expecting: sha512(user + ':' + password)

    if (!suspect) return
    if (!this._isValid(suspect)) {
      if (this._invalids.hasOwnProperty(loc)) this._invalids[loc]++
      else this._invalids[loc] = 1
      if (this._invalids[loc] >= this._opts.maxTries) this._blacklist.push(loc)
      return
    }

    this._onauth(socket)
  }

module.exports = NetGate
