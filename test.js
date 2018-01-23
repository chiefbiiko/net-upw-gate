var tape = require('tape')
var net = require('net')
var crypto = require('crypto')
var EC = require('elliptic').ec
var ec = new EC('curve25519')

var netGate = require('./index')
var ellGate = require('./index3').createGate
var clientEstablish = require('./index3').clientEstablish

function sha512 (buf) {
  return crypto.createHash('sha512').update(buf).digest()
}

tape('unencrypted authentication', function (t) {

  var cred = sha512('chiefbiiko:fraud')

  var gate = netGate([ cred ], onauth)
  var server = net.createServer(gate)
  var client

  function onauth (socket) {
    t.true(true, 'authenticated successfully')
    client.destroy()
    server.close()
    t.end()
  }

  server.listen(10000, 'localhost', function () {
    client = net.connect(10000, 'localhost', function () {
      client.write(cred)
    })
  })

})

tape('encrypted authentication', function (t) {

  var cred = sha512('chiefbiiko:fraud')

  var gate = ellGate([ cred ], onauth)
  var server = net.createServer(gate)

  function onauth (socket) {
    t.true(true, 'authenticated successfully')
    socket.end()
    socket.destroy()
    server.close()
    t.end()
  }

  server.listen(10000, 'localhost', function () {
    var client = net.connect(10000, 'localhost', function () {
      clientEstablish(client, cred)
    })
  })

})
