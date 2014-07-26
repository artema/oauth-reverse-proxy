oauth-reverse-proxy
===================

Express/Connect middleware for reverse proxying OAuth 1 web services. Can be used to perform OAuth-protected service calls without exposing consumer and token key pairs on the client side.

# Usage

	var app = require('express')();
	var when = require('when');

	app.use(require('oauth-reverse-proxy').oauth1({
		endpoint: '/api/',
		target: 'https://api.twitter.com/1.1/',
		provider: function(req) {
			return when({
				consumerKey: 'eWudHldSbIaelX7swmsiHImEL4KinwaGloHANdrY',
				consumerSecret: '2EEfA6BG3ly3sR3RjE0IBSnlQu4ZrUzPiYKmrkVU',
				tokenKey: 'Z6eEdO8MOmk394WozF5oKyuAv855l4Mlqo7hhlSLik',
				tokenSecret: 'Kd75W4OQfb2oJTV0vzGzeXftVAwgMnEK9MumzYcM'
			});
		},
		credentials: {
			consumerKey: 'eWudHldSbIaelX7swmsiHImEL4KinwaGloHANdrY',
			consumerSecret: '2EEfA6BG3ly3sR3RjE0IBSnlQu4ZrUzPiYKmrkVU',
			tokenKey: 'Z6eEdO8MOmk394WozF5oKyuAv855l4Mlqo7hhlSLik',
			tokenSecret: 'Kd75W4OQfb2oJTV0vzGzeXftVAwgMnEK9MumzYcM'
		}
	}));
  
`endpoint`: Website path that will be used as an endpoint for API requests.
`target`: Target API URL.
`provider`: OAuth credentials provider. A Function that will be invoked for each API request. Takes `req` argument with the current request object. Must return a promise with a credentials object, `{}` for unauthorized API calls or `null` to send a 401 error to a client.
`credentials` (optional): static OAuth credentials to use for all requests.
`signatureMethod` (optional): OAuth signature method. Defaults to `HMAC-SHA1`.
`keepCookies` (optional): Keep cookies header in API requests. Defaults to `false`.
