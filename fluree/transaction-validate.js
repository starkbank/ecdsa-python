#!/usr/bin/node
let fluree_utils = require('@fluree/crypto-utils');
let fluree_crypto = require('@fluree/crypto-base');
let privkey = "bf8a7281f43918a18a3feab41d17e84f93b064c441106cf248307d87f8a60453"
let pub_key = fluree_crypto.pub_key_from_private(privkey);
var fs = require('fs');
var obj = JSON.parse(fs.readFileSync(0, 'utf-8'));
var payload = obj["cmd"];
var signature = obj["sig"];
try {
    if (fluree_crypto.verify_signature(pub_key, payload, signature)) {
        console.log("OK");
    } else {
        console.log("FAIL");
    }
} 
catch (err) {
    console.log("FAIL:", err.message)
}

