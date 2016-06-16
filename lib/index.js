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
    validateToken: Joi.func(),
    getGoogleCerts: Joi.func(),
    urlKey: Joi.boolean(),
    cookieKey: Joi.boolean(),
    headerKey: Joi.boolean()
  },
  _getGoogleCerts: function(kid, callback){
    /* istanbul ignore next */
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
  settings.getGoogleCerts = settings.getGoogleCerts || internals._getGoogleCerts;
  settings.validateToken = settings.validateToken || function(x, y, cb){cb();};
  return {
    authenticate: function(request, reply){
      const token = extract(request, settings);

      if (!token) {
        return reply(Boom.unauthorized(null, 'id token', 'ID token required.'));
      }

      request.auth.token = token; // keep encoded JWT available in the request lifecycle

      const decodedToken = jwt.decode(token, {complete: true, json: true});
      // Validate issuers and audience
      const valid_issuers = [
        "accounts.google.com",
        "https://accounts.google.com"
      ];
      if (!decodedToken) {
        return reply(Boom.unauthorized("Malformed id token."));
      } else if (valid_issuers.indexOf(decodedToken.payload.iss) === -1) {
        return reply(Boom.unauthorized("JWT issuer invalid."));
      } else if (decodedToken.payload.aud !== settings.clientId) {
        return reply(Boom.unauthorized("JWT audience invalid."));
      }
      
      return settings.getGoogleCerts(decodedToken.header.kid, function(err, cert) {
        if (err || !cert) {
          return reply(Boom.unauthorized("Failure fetching certificate.", err));
        }
        
        return jwt.verify(token, cert, function(err) {
          if (err) {
            return reply(Boom.unauthorized("Unable to verify id token."));
          }
          
          return settings.validateToken(decodedToken, request, function(err, newToken){
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
