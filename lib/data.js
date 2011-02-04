/**
   OAuth server data storages.
   Copyright(c) 2011 selead
   MIT Licensed
 */

/**
   Module dependencies.
 */

Consumer = function (params) {
//name, descr, key, secret, callbackUrl, accessType, url) {
    this.name = params.name || '';
    this.descr = params.descr || '';
    this.key = params.key;
    this.secret = params.secret;
    this.accessType = params.accessType || 'r';
    this.callbackUrl = params.callbackUrl || '';
    this.url = params.url || '';
};


// todo update docs
/**
   Token object.

   @param {String} key Token public key.
   @param {String} secret Token private key.
   @api public
 */
RequestToken = function (key, secret, consumerKey, userID) {
    this.key = key;
    this.secret = secret;
    this.consumerKey = consumerKey;
    this.userID = userID;
};

AccessToken = function (key, secret, consumerKey, userID, accessType) {
    this.key = key;
    this.secret = secret;
    this.consumerKey = consumerKey;
    this.userID = userID;
    this.accessType = accessType || 'r';
    this.createdAt = new Date();
    this.freeze = false;
};



exports.RequestToken = RequestToken;
exports.AccessToken = AccessToken;
exports.Consumer = Consumer;

