var Hapi   = require('hapi');
var clientId = "aclientid";

// for debug options see: http://hapijs.com/tutorials/logging
var server = new Hapi.Server();
// server.connection({ port: 3000 });
server.connection();

var db = {
  "123": { allowed: true,  "name": "Charlie"  },
  "321": { allowed: false, "name": "Old Gregg"}
};

// defining our own validate function lets us do something
// useful/custom with the decodedToken before reply(ing)
var validate = function (decoded, request, callback) {
  if (db[decoded.payload.id].allowed) {
    return callback(null);
  }
  else {
    return callback("ID not in test DB.");
  }
};

var fakeGoogleCert = function(kid, callback){
  callback(null, 'afakegooglecert');
};

var home = function(req, reply) {
  return reply('Hai!');
};

var privado = function(req, reply) {
  return reply('worked');
};

var sendToken = function(req, reply) {
  return reply(req.auth.token);
};

server.register(require('../'), function () {

  server.auth.strategy('token', 'google-id-token', {
    clientId,
    validateToken: validate,
    getGoogleCerts: fakeGoogleCert
  });

  server.auth.strategy('token-nourl', 'google-id-token', {
    clientId,
    validateToken: validate,
    urlKey: false,
    getGoogleCerts: fakeGoogleCert
  });

  server.auth.strategy('token-nocookie', 'google-id-token', {
    clientId,
    validateToken: validate,
    cookieKey: false,
    getGoogleCerts: fakeGoogleCert
  });

  server.route([
    { method: 'GET',  path: '/', handler: home, config: { auth: false } },
    { method: 'GET', path: '/token', handler: sendToken, config: { auth: 'token' } },
    { method: 'POST', path: '/privado', handler: privado, config: { auth: 'token' } },
    { method: 'POST', path: '/privadonourl', handler: privado, config: { auth: 'token-nourl' } },
    { method: 'POST', path: '/privadonocookie', handler: privado, config: { auth: 'token-nocookie' } },
    { method: 'POST', path: '/required', handler: privado, config: { auth: { mode: 'required', strategy: 'token' } } },
    { method: 'POST', path: '/optional', handler: privado, config: { auth: { mode: 'optional', strategy: 'token' } } },
    { method: 'POST', path: '/try', handler: privado, config: { auth: { mode: 'try', strategy: 'token' } } }
  ]);

  // When debugging tests, running the actual server is userful.
  // server.start(function(err) {
  //   if (err) {
  //     console.error('Server failed to start:', err);
  //   } else {
  //     console.info('Server running at:', server.info.uri);
  //   }
  // });
});

module.exports = server;
