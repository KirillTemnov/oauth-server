/**
   Note: Before use example.com domain, make sure, that you add alias 127.0.0.1 to hosts file.

   This module depends on oauth and connenct, that may be installed via
     npm install oauth connect
 */


var sys = require('sys'),
    connect = require('connect'),
    url = require('url'),
    OAuth = require('oauth').OAuth;
    consumer = new OAuth('http://example.com:4000/oauth/request-token',
                    'http://example.com:4000/oauth/access-token',
                    'key', 'secret', '1.0A',
                    'http://example.com:3000//oauth/example.com/verify', 'HMAC-SHA1');

function app(app) {
    app.get('/', function(req, res){
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.write('Test consumer for oauth-server. <br />'+
                  '<a href="/test-oauth-server"> Click link </a> to start test');
        res.end();
    });
    app.get('/test-oauth-server', function (req, res) {
        consumer.getOAuthRequestToken(function(error, oauth_token, oauth_token_secret, results ){
            if (error) {
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.write('Error in request: ' + sys.inspect(error));
                res.end();
            } else {
                res.writeHead(302, { Location:
                                     'http://example.com:4000/oauth/authorize?oauth_token=' +
                                     oauth_token});
                var tok = {oauth_token: oauth_token, oauth_token_secret: oauth_token_secret};
                req.session['oauth-token'] = tok;
                res.end();
            }
        });
    });
    app.get('/oauth/example.com/verify', function (req, res) {
        consumer.getOAuthAccessToken(req.session['oauth-token'].oauth_token,
                                req.session['oauth-token'].oauth_token_secret,
                                url.parse(req.url, true).query.oauth_verifier,
                                function(error, oauth_access_token,
                                         oauth_access_token_secret) {
                                    if (error === null) {
                                        req.session.oauth_access_token = oauth_access_token;
                                        req.session.oauth_access_token_secret =
                                            oauth_access_token_secret;
                                        res.writeHead(200, { 'Content-Type': 'text/html'});
                                        res.write('<a href="http://example.com:4000/oauth/protected-resource?oauth_token=' +
                                                  oauth_access_token + '&oauth_token_secret=' +
                                                  oauth_access_token_secret + '"> Access protected resource! </a>');
                                   } else {
                                       res.writeHead(500, { 'Content-Type': 'text/html' });
                                       res.write('Error: ' + sys.inspect(error));
                                   }
                                   res.end();
                               });

    });
}

var server = connect.createServer(
    connect.bodyParser(),
    connect.cookieParser(),
    connect.session({secret: 'change-me'}),
    connect.router(app),
    connect.errorHandler({ dumpExceptions: true, showStack: true })
).listen(3000);
