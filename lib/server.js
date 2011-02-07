var sys = require('sys'),
qs = require('querystring');

var util = require('./util'),
checkRequest = util.checkRequest,
generateRequestToken = util.generateRequestToken,
generateAccessToken = util.generateAccessToken,
URL = require('url'),
http = require('http');


// todo take some code from
// https://github.com/senchalabs/connect/blob/master/lib/connect/index.js


/**
   Get request token.

   @param {Object} query Query object, that contains oauth_token and may contain oauth_verifier.
   @param {Store} store OAuthMemoryStore object.
   @param {Function} callback Callback, that accepts request token or null as a first param.
 */
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

/**
   Write invalid url message to responce.

   @param {Object} res Responce object.
 */ // todo #refactor
function invalidUrl (res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.write('Url invalid');
    res.end();
}

/**
   Create oauth server object.

   @param {String} domain Domain name.
   @param {Object} actions OAuthServer actions to override.
   @param {Object} protectedActions OAuthServer protected actions.
   @param {Object} store OAuth store object (e.q. OAuthMemoryStore).
   @api public
 */ // todo #implement
OAuthServer = function (domain, actions, protectedActions, store) {
    this._domain = domain;
    this._stack = [];
    this._port = domain.indexOf(':') > 0 ? parseInt(domain.split(':')[1]) : 80;
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
    this._actions = {
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

    this._protectedActions = protectedActions;

//    var self = this;
    this._server = http.createServer(this.handle);
}

/**
   Route function, override it to change routing logic.

   @param {Object} req Request object.
   @param {Object} res Responce object.
   @api public
 */ // todo #implement
OAuthServer.prototype.router = function (req, res) {
    this.handle(req, res);
    var url = URL.parse(req.url).pathname; // todo regexp search
    if (typeof this._actions[url] === 'function') {
        this._actions[url](req, res, this.store);
    }
    else if (typeof this._protectedActions[url] === 'function' ){
        this._protectedActions[url](req, res, this.store);
    }
    else {
        invalidUrl(res);
        // error, page not found
    }
}

/**
   Request handler function. Responds to middleware.

   @param {Object} req Request object.
   @param {Object} res Responce object.
   @api public
 */ // todo #implement
OAuthServer.prototype.handle = function (res, req) {
    var index = 0;

    // todo write handle stack 
    this.router(req, res);
}

/**
   Add new route to server.

   @param {String} url Url for route. In case of one paremeter, method use it as a handler,
                       and set url to '/'.
   @param {Function} handler Handler function.
   @api public
 */ // todo #implement
OAuthServer.prototype.use = function (url, handler) {
    if (typeof url !== 'string') {
        handler = url;
        url = '/';
    }
    

}

/**
   Start listening on predefined port.

   @api public
 */
OAuthServer.prototype.listen = function () {
    this._server.listen(this._port);
}

/**
   Add new action.

   @param {String} url Url for action.
   @param {Function} action Action function (hanler).
   @param {Boolean} isProtected If action protected, it will require valid access token.
   @api public
 */  // todo #refactor This method partially duplicate `use` method.
OAuthServer.prototype.addAction = function (url, action, isProtected) {
    if (isProtected) {
        this._protectedActions[url] = action;
    }
    else {
        this._actions[url] = action;
    }
}

/**
   Remove action from router
   
   
 */ // todo #refactor should I remove this method?
OAuthServer.prototype.removeAction = function (url, isProtected) {
    isProtected ? delete protectedActions[url] : actions[url];
}

module.exports = OAuthServer;
