var tape = require('tape')
var net = require('net')
var crypto = require('crypto')

var NetGate = require('./index2')

function sha512 (buf) {
  return crypto.createHash('sha512').update(buf).digest()
}

tape('auth', function (t) {

  function onauth (socket) {
    t.true(true, 'authenticated successfully')
    server.close()
    t.end()
  }

  var cred = sha512('chiefbiiko:fraud')

  var gate = NetGate([ cred ], onauth)
  var server = net.createServer(gate.protect.bind(gate))

  server.listen(10000, 'localhost', function () {
    var client = net.connect(10000, 'localhost', function () {
      client.write(cred)
    })
  })

})
