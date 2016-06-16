var test   = require('tape');
var JWT    = require('jsonwebtoken');
var secret = 'afakegooglecert';
var tokenOptions = {issuer: "accounts.google.com", audience: "aclientid"};

var server = require('./basic_server'); // test server which in turn loads our module

test("Attempt to access restricted content (without auth token)", function(t) {
  var options = {
    method: "POST",
    url: "/privado"
  };
  // server.inject lets us simulate an http request
  server.inject(options, function(response) {
    t.equal(response.result.message, "Missing authentication", "Correct error message.");
    t.equal(response.statusCode, 401, "No Token should fail");
    t.end();
  });
});

test("Attempt to access restricted content (with an INVALID Token)", function(t) {
  var options = {
    method: "POST",
    url: "/privado",
    headers: { authorization: "Bearer fails.validation" }
  };
  server.inject(options, function(response) {
    t.equal(response.statusCode, 401, "INVALID Token should fail");
    t.equal(response.result.message, "Malformed id token.", "Correct error message.");
    t.end();
  });
});

test("Malformed JWT", function(t) {
  // use the token as the 'authorization' header in requests
  var options = {
    method: "POST",
    url: "/privado",
    headers: { authorization: "Bearer my.invalid.token" }
  };
  server.inject(options, function(response) {
    t.equal(response.statusCode, 401, "INVALID Token should fail");
    t.equal(response.result.message, "Malformed id token.", "Correct error message.");
    t.end();
  });
});

test("Token is well formed but is allowed=false so should be denied", function(t) {
  var token = JWT.sign({ id: 321, "name": "Old Gregg" }, secret, tokenOptions);
  var options = {
    method: "POST",
    url: "/privado",
    headers: { authorization: "Bearer " + token }
  };
  server.inject(options, function(response) {
    t.equal(response.statusCode, 401, "Denied");
    t.equal(response.result.message, "Error validating id token.", "Correct error message.");
    t.end();
  });
});

test("Access restricted content (with VALID Token)", function(t) {
  var token = JWT.sign({ id: 123, "name": "Charlie" }, secret, tokenOptions);
  var options = {
    method: "POST",
    url: "/privado",
    headers: { authorization: "Bearer " + token }
  };
  server.inject(options, function(response) {
    t.equal(response.statusCode, 200, "VALID Token should succeed!");
    t.end();
  });
});

test("Access restricted content (with Well-formed but invalid Token)", function(t) {
  var token = JWT.sign({ id: 123, "name": "Charlie" }, 'badsecret', tokenOptions);
  var options = {
    method: "POST",
    url: "/privado",
    headers: { authorization: "Bearer " + token }
  };
  server.inject(options, function(response) {
    t.equal(response.statusCode, 401, "Invalid Token should Error!");
    t.equal(response.result.message, 'Unable to verify id token.', "Correct error message.");
    t.end();
  });
});

test("Request with undefined auth header should 401", function(t) {
  var options = {
    method: "POST",
    url: "/privado",
    headers: { authorization: "Bearer " }
  };
  server.inject(options, function(response) {
    t.equal(response.statusCode, 401, "Invalid Token fails (as expected)!");
    t.equal(response.result.message, "Missing authentication", "Correct error message.");
    t.end();
  });
});

test("Auth mode 'required' should require authentication header", function(t) {
  var options = {
    method: "POST",
    url: "/required"
  };
  // server.inject lets us simulate an http request
  server.inject(options, function(response) {
    t.equal(response.statusCode, 401, "No token header should fail in auth 'required' mode");
    t.equal(response.result.message, "Missing authentication", "Correct error message.");
    t.end();
  });
});

test("Auth mode 'required' should fail with invalid token", function(t) {
  // use the token as the 'authorization' header in requests
  var token = JWT.sign({ id: 123, "name": "Charlie" }, 'badsecret', tokenOptions);
  var options = {
    method: "POST",
    url: "/required",
    headers: { authorization: "Bearer " + token }
  };
  server.inject(options, function(response) {
    t.equal(response.statusCode, 401, "Invalid token should error!");
    t.equal(response.result.message, "Unable to verify id token.", "Correct error message.");
    t.end();
  });
});

test("Auth mode 'required' should pass with valid token", function(t) {
  var token = JWT.sign({ id: 123, "name": "Charlie" }, secret, tokenOptions);
  var options = {
    method: "POST",
    url: "/required",
    headers: { authorization: "Bearer " + token }
  };
  server.inject(options, function(response) {
    t.equal(response.statusCode, 200, "Valid token should succeed!");
    t.end();
  });
});

test("Auth mode 'optional' should pass when no auth header specified", function(t) {
  var options = {
    method: "POST",
    url: "/optional"
  };
  server.inject(options, function(response) {
    t.equal(response.statusCode, 200, "No auth header should pass in optional mode!");
    t.end();
  });
});

test("Auth mode 'optional' should fail with invalid token", function(t) {
  var token = JWT.sign({ id: 123, "name": "Charlie" }, 'badsecret', tokenOptions);
  var options = {
    method: "POST",
    url: "/optional",
    headers: { authorization: "Bearer " + token }
  };
  server.inject(options, function(response) {
    t.equal(response.statusCode, 401, "Invalid token should error!");
    t.equal(response.result.message, "Unable to verify id token.", "Correct error message.");
    t.end();
  });
});

test("Auth mode 'optional' should pass with valid token", function(t) {
  var token = JWT.sign({ id: 123, "name": "Charlie" }, secret, tokenOptions);
  var options = {
    method: "POST",
    url: "/optional",
    headers: { authorization: "Bearer " + token }
  };
  server.inject(options, function(response) {
    t.equal(response.statusCode, 200, "Valid token should succeed!");
    t.end();
  });
});

test("Auth mode 'try' should pass when no auth header specified", function(t) {
  var options = {
    method: "POST",
    url: "/try"
  };
  server.inject(options, function(response) {
    t.equal(response.statusCode, 200, "No auth header should pass in 'try' mode!");
    t.end();
  });
});

test("Auth mode 'try' should pass with invalid token", function(t) {
  var token = JWT.sign({ id: 123, "name": "Charlie" }, 'badsecret', tokenOptions);
  var options = {
    method: "POST",
    url: "/try",
    headers: { authorization: "Bearer " + token }
  };
  server.inject(options, function(response) {
    t.equal(response.statusCode, 200, "Invalid token should pass in 'try' mode");
    t.end();
  });
});

test("Auth mode 'try' should pass with valid token", function(t) {
  var token = JWT.sign({ id: 123, "name": "Charlie" }, secret, tokenOptions);
  var options = {
    method: "POST",
    url: "/try",
    headers: { authorization: "Bearer " + token }
  };
  server.inject(options, function(response) {
    t.equal(response.statusCode, 200, "Valid token should succeed!");
    t.end();
  });
});

test("Scheme should set token in request.auth.token", function(t) {
  var token = JWT.sign({ id: 123, "name": "Charlie" }, secret, tokenOptions);
  var options = {
    method: "GET",
    url: "/token",
    headers: { authorization: "Bearer " + token }
  };
  server.inject(options, function(response) {
    t.equal(response.result, token, 'Token is accesible from handler');
    t.end();
  });
});

test.onFinish(function () {
  server.stop(function(){});
})
