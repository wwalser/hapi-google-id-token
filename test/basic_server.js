var Hapi = require('hapi');
var Boom = require('boom');
var clientId = "aclientid";

// for debug options see: http://hapijs.com/tutorials/logging
var server = new Hapi.Server();
// server.connection({ port: 3000 });
server.connection();

var db = {
  "123": { allowed: true,  "name": "Charlie"  },
  "321": { allowed: false, "name": "Old Gregg"},
  'boom': {
    allowed: false,
    name: "Boom boom boom",
    error: Boom.unsupportedMediaType("Very strange error (test).")
  }
};

// defining our own validate function lets us do something
// useful/custom with the decodedToken before reply(ing)
var validate = function (decoded, request, callback) {
  const entry = db[decoded.payload.id];
  if (!entry.allowed) {
    if (db[decoded.payload.id].error) {
      return callback(db[decoded.payload.id].error);
    }

    return callback("ID not in test DB.");
  }
  //pass validation
  return callback(null);
};

var fakeGoogleCert = function(kid, callback){
  callback(null, 'afakegooglecert');
};

var badGoogleCert = function(kid, callback){
  callback('cert not found');
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

  server.auth.strategy('token-badcert', 'google-id-token', {
    clientId,
    validateToken: validate,
    getGoogleCerts: badGoogleCert
  });

  server.route([
    { method: 'GET',  path: '/', handler: home, config: { auth: false } },
    { method: 'GET', path: '/token', handler: sendToken, config: { auth: 'token' } },
    { method: 'POST', path: '/privado', handler: privado, config: { auth: 'token' } },
    { method: 'POST', path: '/privadonourl', handler: privado, config: { auth: 'token-nourl' } },
    { method: 'POST', path: '/privadonocookie', handler: privado, config: { auth: 'token-nocookie' } },
    { method: 'POST', path: '/privadobadcert', handler: privado, config: { auth: 'token-badcert' } },
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
