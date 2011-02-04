/**
   Initialize OAuthMemoryStore with optons.

   @param {Object} opts Options.
   @api public
 */
OAuthMemoryStore  = function (opts) {
    this.consumers = {};
    this.accessTokens = {};
    this.requestTokens = {};
};

/**
   Add new consumer to OAuthMemoryStore.

   @param {Object} consumer New consumer.
   @param {String} consumer.key Consumer public key.
   @param {String} consumer.secret Consumer private key.
   @param {String} consumer.name  Consumer display name.
   @api public
 */
OAuthMemoryStore.prototype.addConsumer = function (consumer) {
    this.consumers[consumer.key] = consumer;
};

/**
   Remove consumer in OAuthMemoryStore by a public key.

   @param {String} key Consumer public key.
   @api public
 */
OAuthMemoryStore.prototype.removeConsumer = function (key) {
    delete this.consumers[key]; // splice ?
};

/**
   Search for consumer in OAuthMemoryStore by a public key.

   @param {String} key Consumer public key.
   @return {Object} fn Callback function.
   @api public
 */
OAuthMemoryStore.prototype.lookupConsumer = function (key, fn) {
    fn(typeof this.consumers[key] === 'undefined' ? null : this.consumers[key]);
};

/**
   Lookup token in tokens dictionary.

   @param {Object} consumer Consumer object.
   @param {String} tokenKey Token key.
   @param {Object} store Dictionary with tokens.
   @return {Token|null} token Token object.
   @api private
 */
OAuthMemoryStore.prototype._lookupToken = function (tokenKey, store) {
    var tok = store[tokenKey];
    return (tok) ? tok : null;
    // if (tok && tok.consumerKey === consumer.key) { // wtf ???
    //     return tok;
    //     for (var i in tok.consumerApps) {
    //         if (tok.consumerApps[i].key === consumer.key) {
    //             return tok;
    //         }
    //     }
    // }
    // return null;
}

/**
   Lookup request token in OAuthMemoryStore.

   @param {String} tokenKey Request token key.
   @return {Object} fn Callback function.
   @api public
 */
OAuthMemoryStore.prototype.lookupRequestToken = function (tokenKey, fn) {
    fn(this._lookupToken(tokenKey, this.requestTokens));
};

/**
   Lookup access token in OAuthMemoryStore.

   @param {String} tokenKey Access token key.
   @return {Object} fn Callback function.
   @api public
 */
OAuthMemoryStore.prototype.lookupAccessToken = function (tokenKey, fn) {
    fn(this._lookupToken(tokenKey, this.accessTokens));
};

/**
   Add token to store.

   @param {Token} token Token to add.
   @param {Object} store Dict to save token.
   @api private
 */
OAuthMemoryStore.prototype._addToken = function (token, store) {
    store[token.key] = token;
};

/**
   Add request token to OAuthMemoryStore.

   @param {Token} token Request token.
   @api public
 */
OAuthMemoryStore.prototype.addRequestToken = function (token) {
    return this._addToken(token, this.requestTokens);
};

/**
   Add access token to OAuthMemoryStore.

   @param {Token} token Access token.
   @api public
 */
OAuthMemoryStore.prototype.addAccessToken = function (token) {
    return this._addToken(token, this.accessTokens);
};

/**
   Remove token from store.

   @param {Token} token Token to remove.
   @param {Object} store Store for tokens.
   @api private
 */
OAuthMemoryStore.prototype._removeToken = function (token, store) {
    delete store[token.key];
};

/**
   Remove request token.

   @param {Token} token Token to remove.
   @api public
 */
OAuthMemoryStore.prototype.removeRequestToken = function (token) {
    this._removeToken(token, this.requestTokens);
};

OAuthMemoryStore.prototype.authorizeRequestToken = function (token, user) {

};

exports.OAuthMemoryStore = OAuthMemoryStore;