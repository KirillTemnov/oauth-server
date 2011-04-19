Server-side implementation of OAuth 1.0A protocol.
==================================================

Installation:
    npm install oauth-server



Usage example:
--------------

Add example.com to your hosts file: 

    echo "127.0.0.1	example.com" >> /etc/hosts


Launch in console from repo root:

    node examples/server.js&
    node examples/consumer.js&

Browse to http://example.com:3000 and follow instructions

*Note* 
------
 This server handles requests for one (anonimous) user. Add store with users and connect them with
 access keys. If you will test both server and consumer, set various domain names, because consumer
 and oauth server *must have different cookie files*


