/**
   Note: Before use example.com domain, make sure, that you add alias 127.0.0.1 to hosts file.
 */

var oasrv = require('oauth-server'),
Server = oasrv.server.OAuthServer,
memStore = oasrv.store.memory.OAuthMemoryStore,
store = new memStore();
Consumer = oasrv.Consumer;

var URL = require('url'),
qs = require('querystring');

store.addConsumer(
    new Consumer({name:'oauth-test-consumer', key:'key', secret:'secret',
                  callbackUrl: 'http://example.com:3000/oauth/example.com/verify'}));

server = new Server('example.com:4000', {}, {}, 4000, store);

server.addAction('/oauth/protected-resource',
                 function (req, res, store) {
                     var query = qs.parse((URL.parse(req.url)).query);
                     var params = {};
                     console.log('ACCESS to protected resource\n');
                     if (req.method.toUpperCase() === 'GET') {
                         params = query;
                         store.lookupAccessToken(params.oauth_token, function (token) {
                             if (token && token.secret === params.oauth_token_secret) {
                                 res.writeHead(200, {'Content-Type': 'text/html'});
                                 res.write('<h1> Access granted! </h1>');
                             } else {
                                 res.writeHead(403, {'Content-Type': 'text/plain'});
                                 res.write('Invalid token');
                             }
                             res.end();
                         });
                     } else if (req.method.toUpperCase() === 'POST') {
                         // todo
                     } else {
                         invalidUrl();
                     }
                 }, true);

server.listen();
