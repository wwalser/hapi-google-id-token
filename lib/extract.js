var Cookie = require('cookie'); // highly popular decoupled cookie parser

 /**
  * Extract the JWT from URL, Auth Header or Cookie
  */

module.exports = function (request, options) {
  // The key holding token value in url or cookie defaults to token
  var urlKey    = options.urlKey === false || typeof options.urlKey === 'string' ? options.urlKey : 'id_token';
  var cookieKey = options.cookieKey === false || typeof options.cookieKey === 'string' ? options.cookieKey : 'id_token';
  var headerKey = options.headerKey === false || typeof options.headerKey === 'string' ? options.headerKey : 'authorization';
  var auth;

  if(urlKey && request.query[urlKey]) {
    auth = request.query[urlKey];
  }
  else if (headerKey && request.headers[headerKey]) {
    if (typeof options.tokenType === 'string') {
      var token = request.headers[headerKey].match(new RegExp(options.tokenType + '\\s+([^$]+)', 'i'));
      auth = token === null ? null : token[1];
    } else {
      auth = request.headers[headerKey];
    }
  }
  else if (cookieKey && request.headers.cookie) {
    auth = Cookie.parse(request.headers.cookie)[cookieKey];
  }

  // strip pointless "Bearer " label & any whitespace > http://git.io/xP4F
  return auth ? auth.replace(/Bearer/gi, '').replace(/ /g, '') : null;
};
