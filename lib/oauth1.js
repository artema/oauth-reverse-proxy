//lib/oauth1.js

var oauthSignature = require('oauth-signature');
var when = require('when');
var httpProxy = require('http-proxy');
var urlUtil = require('url');

var NONCE_CHARACTERS = '0123456789abcdefghiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXTZ';

var generateNonce = function(length) {
    var nonce = '';
    for (var i = 0; i < length; i++) {
        var random = Math.floor(Math.random() * NONCE_CHARACTERS.length);
        nonce += NONCE_CHARACTERS.substring(random, random + 1);
    }
    return nonce;
};

module.exports = function(config){
  if (!config) throw new Error('No config provided.');
  if (!config['target'] && typeof config['target'] != 'string') throw new Error('Missing or invalid target URL.');
  if (!config['endpoint'] && typeof config['endpoint'] != 'string') throw new Error('Missing or invalid endpoint URL.');
  if (!config['provider'] && !config['credentials']) throw new Error('Missing credentials or provider.');

  if (config['credentials']) {
    config['provider'] = function(req) {
      return when(config['credentials']);
    };
  }

  if (!config['signatureMethod'])
    config['signatureMethod'] = 'HMAC-SHA1';

  if (config['target'].substring(config['target'].length - 1) != '/')
    config['target'] += '/';

  if (config['endpoint'].substring(config['endpoint'].length - 1) != '/')
    config['endpoint'] += '/';

  config['target'] = urlUtil.parse(config['target']);

  var proxy = httpProxy.createProxyServer({});

  var buildOAuthHeader = function(req, credentials) {
    var nonce = generateNonce(32),
    timestamp = Math.floor(new Date().getTime() / 1000).toString();

    var url = config['target'].protocol + '//' + config['target'].host + req.url;
    var query = urlUtil.parse(req.url, true).query;

    var parameters = {};

    for (var key in query) {
        parameters[key] = query[key];
    }

    if (credentials.consumerKey)
       parameters.oauth_consumer_key = credentials.consumerKey;

    if (credentials.tokenKey)
      parameters.oauth_token = credentials.tokenKey;

    parameters.oauth_nonce = nonce;
    parameters.oauth_timestamp = timestamp;
    parameters.oauth_signature_method = config['signatureMethod'];
    parameters.oauth_version = '1.0';

    var xAuthMode = credentials.xAuthUsername && credentials.xAuthPassword ? 'client_auth' : null,
    signature = oauthSignature.generate(
      req.method,
      url,
      parameters,
      credentials.consumerSecret,
      credentials.tokenSecret
    ),
    header = 'OAuth ' +
      'oauth_nonce="' + nonce + '"' +
      (credentials.tokenKey ? ',oauth_token="' + credentials.tokenKey + '"' : '') +
      ',oauth_signature_method="' + parameters.oauth_signature_method + '"' +
      ',oauth_timestamp="' + timestamp + '"' +
      (credentials.consumerKey ? ',oauth_consumer_key="' + credentials.consumerKey + '"' : '') +
      ',oauth_signature="' + signature + '"' +
      ',oauth_version="' + parameters.oauth_version + '"' +
      (config['oauthRealm'] ? ',realm="' + config['oauthRealm'] + '"' : '') +
      (xAuthMode ? ',x_auth_mode="' + x_auth_mode + '"' : '') +
      (credentials.xAuthUsername ? ',x_auth_username="' + credentials.xAuthUsername + '"' : '') +
      (credentials.xAuthPassword ? ',x_auth_password="' + credentials.xAuthPassword + '"' : '');

    return header;
  };

  return function(req, res, next){
    if (req.url.substring(0, config['endpoint'].length) != config['endpoint']) {
      next();
      return;
    }

    config['provider'](req).then(function(credentials) {
      if (!credentials) {
        res.send(401);
        res.end();
        return;
      }

      var target = config['target'].protocol + '//' + config['target'].host;
      req.url = config['target'].pathname + req.url.slice(config['endpoint'].length);

      if (!config['keepCookies']) {
        delete req.headers.cookies;
      }

      req.headers.authorization = buildOAuthHeader(req, credentials);
      req.headers.host = config['target'].host;

      proxy.web(req, res, { target: target }, function(e) {
        res.send(502);
        res.end();
        next(e);
        return;
      });
    }, function(e) {
      res.send(500);
      res.end();
      next(e);
      return;
    });
  }
};
