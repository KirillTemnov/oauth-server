/**
   Utils for oauth server.
   
   
 */

var URL = require('url'),
sys = require('sys'),
crypto = require('crypto');
var max_timestamp_delta = 600; // todo 24.02.2011 move this to settings!
// range of verification chars
const verifierSet = 'abcdefghijklmnopqrstuvwxyz0123456789';

/**
   Urlencode data.

   @param {String} data Data to encode.
   @return {String} encodedData Encoded data.
   @api private
 */
var encodeData = function (data) {
    return data === null || data === '' ? "" :
        // replace symbols ! ' ( ) *
        encodeURIComponent(data).replace(/\!/g, "%21").replace(/\'/g, "%27")
                 .replace(/\(/g, "%28").replace(/\)/g, "%29").replace(/\*/g, "%2A");
}

/**
   Urldecode data.

   @param {String} data Data to decode.
   @return {String} encodedData Decoded data.
   @api private
 */
var decodeData = function (data) {
    return decodeURIComponent( data !== null ? data.replace(/\+/g, " ") : data);
}

/**
   Sort parameters in dictionary.

   @param {Object} params Parameters dictionary.
   @return {Object} sortedParams Sorted params dictionary.
   @api private
 */
function sortParams (params) {
    params.sort(function (a, b) {
        if ( a[0] === b[0] ) {
            return a[1] < b[1] ? -1 : 1;
        }
        else {
            return a[0] < b[0] ? -1: 1;
        }});
    return params;
}

/**
   Sign params of request.

   @param {String} method Request method.
   @param {String} url Request url.
   @param {String} signType Sign type, must be "sha1".
   @param {String} secretKey Secret key to sign.
   @param {Object} params Request params.
   @api private
 */
function signParams (method, url, signType, secretKey, params) {
    // todo 24.02.2011 check signType
    for (var i in params) {
        if (params[i][0] === 'oauth_signature') {
            params.splice(i,1);
            break;
        }
    }
    url = encodeData(url)       // todo normalize url

    var baseString = method.toUpperCase() + '&' + url + '&' +
        encodeData(params.map(function (p) { return p.join('='); }).join('&'));
    return crypto.createHmac(signType, secretKey).update(baseString).digest('base64');
}

// check for correct request token
/**
   Check if request token correct.

   @param {Object} req Request object.
   @param {OAuthStore} store Store to lookup request token.
   @param {Function} fn Callback function. If first param of function is null, token correct.
   @api private
 */
exports.checkRequest = function (req, store, fn) {
    var auth = req.headers.authorization.split(' ');
    if (auth[0] === 'OAuth') {
        // parsedParams
        var pp = sortParams(auth[1].replace(/\"/g, '').split(',').map(function (p) {
            return p.split('=')}));
        params = {};
        for (var i in pp) {
            params[pp[i][0]] = pp[i][1];
        }
        store.lookupConsumer(params.oauth_consumer_key, function (consumer) {
            if (consumer) {
                var signature = params.oauth_signature,
                url = 'http://' + req.headers.host +  URL.parse(req.url).pathname;
                var sig2 = signParams(req.method, url,
                                      'sha1', consumer.secret + '&', pp);
                sig2 = encodeData(sig2);
                fn && fn(signature !== sig2 ? signature : null, params, consumer);
            }
            else { // error
                fn && fn('error: consumer not found!');
            }});
    }
    else {
        fn && fn('Error: missing authorization header');
    }
}

/**
   Check if access token correct.

   @param {Object} req Request object.
   @param {OAuthStore} store Store to lookup access token.
   @param {Function} fn Callback function. If first param of function is null, token correct.
   @api private
 */
exports.checkAccess  = function(req, store, fn) {
    var auth = req.headers.authorization.split(' ');
    if (auth[0] === 'OAuth') {
        console.log('DATA: ' + auth[1] + '\n');
        // parsedParams
        var pp = sortParams(auth[1].replace(/\"/g, '').split(',').map(
            function (p) {
                return p.split('=')}));
        params = {};
        for (var i in pp) {
            params[pp[i][0]] = pp[i][1];
        }
        store.lookupRequestToken(params.oauth_token, function (token) {
            console.log('check access token:\n' + sys.inspect(params) + '\n\n');
            console.log('\ntoken = ' + sys.inspect(token));
            if (token) {
                store.lookupConsumer(params.oauth_consumer_key, function (consumer) {
                if (consumer) {
                    var signature = params.oauth_signature;
                    url = 'http://' + req.headers.host +  URL.parse(req.url).pathname;
                    var sig2 = signParams(req.method, url,
                                          'sha1', consumer.secret + '&' + token.secret, pp);
                    sig2 = encodeData(sig2);
                    var correct = signature === sig2  &&
                        params.oauth_consumer_key === token.consumer.key &&
                        params.oauth_verifier === token.verifier &&
                        // todo safe parsing
                        ((new Date()).getTime() / 1000) - parseInt(params.oauth_timestamp) <
                        max_timestamp_delta;

                    fn && fn(correct ? null : signature, token);
                }
                else { // error
                    fn && fn('error: consumer not found!');
                }});
            }
        });
    }
    else {
        fn && fn('Error: missing authorization header');
    }
}

/**
   Generate key pair.

   @param {String} generatorKey Key to generate pair.
   @param {String} string Base string.
   @param {String} algorithm Hashing algorithm, default - "sha256".
   @param {Object} keyPair Returned key pair contain keys "kay" and "secret".
   @api private
 */
var generateKeypair = function(generatorKey, string, algorithm) {
    algorithm = algorithm || 'sha256';
    var key = crypto.createHmac('sha1', generatorKey).update(new Date()).digest('base64')
        .replace(/\=/g, '.').replace(/\//g, '-').replace(/\+/g, '_');
    var secret = crypto.createHmac(algorithm, key).update(string).digest('base64')
        .replace(/\=/g, '.').replace(/\//g, '-').replace(/\+/g, '_');
    var pair = {key: key, secret: secret};
    return pair;
}

/**
   Generate request token.

   @param {Object} oauthParams OAuth params. Param names must match AOuth 1.0A specification names.
   @param {Consumer} consumer Consumer, that able to use this request token.
   @param {String} algorithm Hashing algorithm.
   @api public
 */
var generateRequestToken = function (oauthParams, consumer, algorithm) {
    var tok = generateKeypair(oauthParams.oauth_nonce, consumer.secret +
                              params.oauth_signature, algorithm);
    tok.nonce = oauthParams.oauth_nonce;
    tok.timestamp = oauthParams.oauth_timestamp;
    tok.consumer = consumer;
    tok.verifier = generateVerifier();
    return tok;
}
exports.generateRequestToken = generateRequestToken;

/**
   Generate access token.

   @param {RequestToken} requestToken RequestToken object.
   @param {String} algorithm Hashing algorithm.
   @api public
 */
// todo 24.02.2011 add userid to access token
var generateAccessToken = function(requestToken, algorithm) {
    var tok = generateKeypair(requestToken.consumer.secret,
                              requestToken.consumer.name + requestToken.secret +
                              requestToken.consumer.callbackUrl, algorithm);
    return tok;
}
exports.generateAccessToken = generateAccessToken;


/**
   Generate verification code.

   @params {Number} size Size of verification code. Optional, default - 20.
   @return {String} code Generated code.
   @api public
 */
var generateVerifier = function (size) {
    var verifier = '';
    size = size || 20;
    for (var i = 0; i < size; i++) {
        verifier += verifierSet[Math.floor(Math.random()*verifierSet.length)];
    }
    return verifier;
}
exports.generateVerifier = generateVerifier;

