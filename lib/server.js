var sys = require('sys'),
qs = require('querystring');

//var Mstore = require('./oauth-store').OAuthMemoryStore,
//Consumer = require('./oauth-server').Consumer,
var util = require('./util'),
checkRequest = util.checkRequest,
generateRequestToken = util.generateRequestToken,
generateAccessToken = util.generateAccessToken,
URL = require('url'),
http = require('http');
//store = new Mstore();



function getRequestToken(query, store, fn) {
    if (typeof query.oauth_token !== 'string') {
        return null;
    }
    var key =  query.oauth_token.replace(/\"/g, '');
    store.lookupRequestToken(key, function (rt) {
        if (rt && query.oauth_verifier) {
            fn(query.oauth_verifier.replace(/\"/g, '') === rt.verifier ? rt : null);
        }
        fn(rt);
    });
}


function invalidUrl (res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.write('Url invalid');
    res.end();
}

/**
   Create oauth server object.

   @param {String} domain Domain name.
   
   
   
   
 */
var OAuthServer = function (domain, actions, protectedActions, port, store) {
    this._domain = domain;

    this.port = port;
    function authorize (req, res, store, allow) {
        if (req.method.toUpperCase() === 'POST') {
            var data = '';
            req.on('data', function (chunk) {
                data += chunk.toString();
            });

            req.on('end', function () {
                getRequestToken(qs.parse(data), store, function (rt) {
                    if (rt) {
                        if (allow) {
                            // todo 
                            // check timestamp and nonce
                            // create access token and sent it to consumer
                            res.writeHead(302, { Location: rt.consumer.callbackUrl +
                                                 '?oauth_token=' + rt.key +
                                                 '&oauth_verifier='+
                                                 rt.verifier + ''});
                            res.end();
                        }
                        else {
                            // todo
                            // deny access
                            // remove request token
                            res.writeHead(200, {'Content-Type': 'text/plain'});
                            res.write('Access from ' + rt.consumer.name + ' declined');
                            res.end();
                        }
                    }
                    else {
                        invalidUrl(res);
                    }
                });
            });
        } else {
            invalidUrl(res);
        }

    }

    this.store = store; // || new require('./oauth-store').OAuthMemoryStore(),
    // todo update actions
    this.actions = {
        '/oauth/request-token': function (req, res, store) {
            if(req.headers.authorization) {
                console.log('STORE = ' + sys.inspect(store));
                checkRequest(req, store, function (error, params, consumer) {
                    // console.log('check request. error = ' + sys.inspect(error));
                    if (! error) {
                        var token = generateRequestToken(params, consumer);
                        store.addRequestToken(token);
                        res.writeHead(200, {'Content-Type': 'text/plain'});
                        res.write('oauth_token='+ token.key + '&oauth_token_secret=' +
                                  token.secret+ '&oauth_callback_confirmed=true');
                        // additional params
                    }
                    else {
                        res.writeHead(404, {'Content-Type': 'text/plain'});
                        console.log(error);
                    }
                    res.end();
                });
            }
            // else { missing authorization
        },
        '/oauth/access-token': function (req, res, store) {
            if (req.method.toUpperCase() === 'POST') {
                var data = '';
                req.on('data', function (chunk) {
                    data += chunk.toString();
                });

                req.on('end', function () {
                    util.checkAccess(req, store, function (error, requestToken) {
                        if (!error) {
                            // save user id!
                            var accessToken = generateAccessToken(requestToken);
                            store.addAccessToken(accessToken);
                            store.removeRequestToken(requestToken);
                            res.writeHead(200, {'Content-Type': 'text/plain'});
                            res.write('oauth_token=' + accessToken.key +
                                      '&oauth_token_secret=' + accessToken.secret);
                        }
                        else {
                            res.writeHead(404, {'Content-Type': 'text/plain'});
                            res.write(error);
                        }
                        res.end();
                    });
                });
            }
            else {
                invalidUrl(res);
            }

        },
        '/oauth/authorize': function (req, res, store) {
            console.log('Inside /oauth/authorize');
            var query = qs.parse((URL.parse(req.url)).query);
            getRequestToken(query, store,  function (rt) {
                if (rt) {
                    res.writeHead(200, {'Content-Type': 'text/html'});
                    var data =
                        '<html> <head> <title> OAuth server test page </title> </head>' +
                        '<body><h1>Allow ' + rt.consumer.name + ' application ? </h1>'+
                        '<form action="/oauth/authorize/allow" method="post">' +
                        '<input name="oauth_token" type="hidden" value="' +
                        rt.key + '" />' +
                        '<input type="submit" value="allow"/> </form>' +
                        '<form action="/oauth/authorize/cancel" method="post">' +
                        '<input name="oauth_token" type="hidden" value="' +
                        rt.key + '" />' +
                        '<input type="submit" value="deny" name="cancel" /><form />' +


                    '</body></html>';
                    res.write(data);
                    res.end();
                }
                else {
                    res.writeHead(403, {'Content-Type': 'text/plain'});
                    res.end('goes wrong');
                }
            });

        },

        '/oauth/authorize/allow': function (req, res) {
            authorize(req, res, store, true);
        },

        '/oauth/authorize/cancel': function (req, res) {
            authorize(req, res, store, false);
        }};

    this.protectedActions = protectedActions;

    var self = this;
    this.server = http.createServer(function (req, res) {
        var url = URL.parse(req.url).pathname; // todo regexp search
        if (typeof self.actions[url] === 'function') {
            self.actions[url](req, res, self.store);
        }
        else if (typeof self.protectedActions[url] === 'function' ){
            self.protectedActions[url](req, res, self.store);
        }
        else {
            invalidUrl(res);
            // error, page not found
        }
    });
}

OAuthServer.prototype.listen = function () {
    this.server.listen(4000); //this.port);
}

OAuthServer.prototype.addAction = function (url, action, isProtected) {
    if (isProtected) {
        this.protectedActions[url] = action;
    }
    else {
        this.actions[url] = action;
    }
}

OAuthServer.prototype.removeAction = function (url, isProtected) {
    isProtected ? delete protectedActions[url] : actions[url];
}

exports.OAuthServer = OAuthServer;
