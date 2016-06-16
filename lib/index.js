const request = require('request');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const Hoek = require('hoek');
const Boom = require('boom');
const pkg = require('../package.json');
const extract = require('./extract');

const internals = {
  schema: {
    clientId: Joi.string().required(),
    verify: Joi.func().required(),
    getGoogleCerts: Joi.func()
  },
  getGoogleCerts: function(kid, callback){
    request({uri: 'https://www.googleapis.com/oauth2/v1/certs'}, function(err, res, body) {
      if (err || !res || res.statusCode != 200) {
        err = err || new Error('error while retrieving Google certs');
        callback(err);
      } else {
        try {
          var keys = JSON.parse(body);
          callback(null, keys[kid]);
        } catch (e) {
          callback(new Error('could not parse certs'));
        }
      }
    });
  }
};

exports.register = function (server, options, next) {
    server.auth.scheme('google-id-token', internals.implementation);
    next();
};

exports.register.attributes = {
  pkg: pkg
};

internals.implementation = function(server, options){
  const results = Joi.validate(options, internals.schema);
  Hoek.assert(!results.error, results.error);

  const settings = results.value;
  settings.getGoogleCerts = settings.getGoogleCerts || internals.getGoogleCerts;
  return {
    authenticate: function(request, reply){
      const token = extract(request, settings);

      if (!token) {
        return reply(Boom.unauthorized('id token required'));
      }

      request.auth.token = token; // keep encoded JWT available in the request lifecycle

      const decodedToken = jwt.decode(token, {complete: true, json: true});
      // Validate payload, issuers and audience
      const valid_issuers = [
        "accounts.google.com",
        "https://accounts.google.com"
      ];
      if (!decodedToken) {
        return reply(Boom.unauthorized("malformed id token"));
      } else if (decodedToken.payload) {
        return reply(Boom.unauthorized("jwt payload invalid"));
      } else if (valid_issuers.indexOf(decodedToken.payload.iss) === -1) {
        return reply(Boom.unauthorized("jwt issuer invalid"));
      } else if (decodedToken.payload.audience === settings.clientId) {
        return reply(Boom.unauthorized("jwt audience invalid"));
      }
      
      return internals.getGoogleCerts(decodedToken.header.kid, function(err, cert) {
        if (err || !cert) {
          reply(Boom.unauthorized("Failure fetching certificate.", err));
        }
        
        return jwt.verify(token, cert, options, function(err) {
          if (err) {
            return reply(Boom.unauthorized("Unable to verify id token."));
          }
          
          return settings.verify(decodedToken, request, function(err, newToken){
            if (err) {
              if (err.isBoom) {
                return reply(err);
              }
              return reply(Boom.unauthorized("Error validating id token.", err));
            }
            
            return reply.continue({credentials: newToken || decodedToken, artifacts: token});
          });
        });
      });
    }
  };
};
