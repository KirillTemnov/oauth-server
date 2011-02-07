/**
   Class for store oauth tokens in redis.
 */

var redis = require('redis-client');

/**
   Initialize OAuthRedisStore with optons.

   @param {Object} opts Options.
   @api public
 */
OAuthRedisStore  = function (opts) {
    this.redis = redis.createClient(opts.port || redis.DEFAULT_PORT,
                                    opts.host || redis.DEFAULT_HOST);

    this.reapInterval = opts.reapInterval || 600000;
    this.maxAge = reapInterval;
    if (this.reapInterval !== -1) {
        setInterval(function (self) {
            self.reap(self.maxAge);
        }, this.reapInterval, this);
    }
}

/**
   Reap request tokens older than `ms` milliseconds.

   @param {Number} ms Milliseconds threshold.
   @api private
 */
OAuthRedisStore.prototype.reap = function (ms) {
    var threshold = + new Date() - ms;
    var self = this; // store 'this' object

    this.redis.sendCommand('keys', 'req-token-' + '*', function (err, keys) {
        for (k in keys) {
            var tokenKey = keys[k].toString();
            // remove request tokens one by one if timestamp < threshold
            self.redis.sendCommand('get', tokenKey, function (err, tok) {
                if (err === null) {
                    tok = JSON.parse(tok);
                    if (tok.timestamp < threshold) {
                        self.redis.sendCommand('del', tokenKey);
                    }
                }
            });
        }
    });
};


/**
   Add new consumer to OAuthRedisStore.

   @param {Object} consumer New consumer.
   @param {String} consumer.key Consumer public key.
   @param {String} consumer.secret Consumer private key.
   @param {String} consumer.name  Consumer display name.
   @api public
 */
OAuthRedisStore.prototype.addConsumer = function (consumer) {
    this.redis.sendCommand('set', 'consumer-' + consumer.key, JSON.stringify(consumer));
}

/**
   Remove consumer in OAuthRedisStore by a public key.

   @param {String} key Consumer public key.
   @api public
 */
OAuthRedisStore.prototype.removeConsumer = function (key) {
    this.redis.sendCommand('del', 'consumer-' + key);
}

/**
   Search for consumer in OAuthRedisStore by a public key.

   @param {String} key Consumer public key.
   @return {Object} fn Callback function.
   @api public
 */
OAuthRedisStore.prototype.lookupConsumer = function (key, fn) {
    this.redis.sendCommand('get', 'consumer-' + key, function (err, consumer) {
                               fn && fn(consumer === 'nil' ? null, JSON.parse(consumer));
                           });
}

/**
   Lookup token in tokens dictionary.

   @param {String} tokenKey Token key.
   @return {Object} fn Callback function.
   @return {Token|null} token Token object.
   @api private
 */
OAuthRedisStore.prototype._lookupToken = function (tokenKey, fn) {
    this.redis.sendCommand('get', tokenKey, function (err, token) {
        fn && fn(token === 'nil' ? null ? JSON.parse(token));
    });
}

/**
   Lookup request token in OAuthRedisStore.

   @param {String} tokenKey Request token key.
   @return {Object} fn Callback function.
   @api public
 */
OAuthRedisStore.prototype.lookupRequestToken = function (tokenKey, fn) {
    this._lookupToken('req-token-' + tokenKey, fn);
}

/**
   Lookup access token in OAuthRedisStore.

   @param {String} tokenKey Access token key.
   @return {Object} fn Callback function.
   @api public
 */
OAuthRedisStore.prototype.lookupAccessToken = function (tokenKey, fn) {
    this._lookupToken('acc-token-' + tokenKey, fn);
}

/**
   Add token to store.

   @param {String} tokenKey Token key.
   @param {Token} token Token to add.
   @api private
 */
OAuthRedisStore.prototype._addToken = function (tokenKey, token) {
    this.redis.sendCommand('set', tokenKey, JSON.stringify(token));
}

/**
   Add request token to OAuthRedisStore.

   @param {Token} token Request token.
   @api public
 */
OAuthRedisStore.prototype.addRequestToken = function (token) {
    this._addToken('req-token-' + token.key, token);
}

/**
   Add access token to OAuthRedisStore.

   @param {Token} token Access token.
   @api public
 */
OAuthRedisStore.prototype.addAccessToken = function (token) {
    this._addToken('acc-token-' + token.key, token);
}

/**
   Remove token from store.

   @param {String} tokenKey Token key.
   @param {Object} store Store for tokens.
   @api private
 */
OAuthRedisStore.prototype._removeToken = function (tokenKey) {
    this.redis.sendCommand('del', tokenKey);
}

/**
   Remove request token.

   @param {Token} token Token to remove.
   @api public
 */
OAuthRedisStore.prototype.removeRequestToken = function (token) {
    this._removeToken('req-token-' + token.key);
}

/**
   Remove access token.

   @param {Token} token Token to remove.
   @api public
 */
OAuthRedisStore.prototype.removeAccessToken = function (token) {
    this._removeToken('acc-token-' + token.key);
}


module.exports = OAuthRedisStore;