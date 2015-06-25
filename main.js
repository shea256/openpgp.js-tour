/* Tour of OpenPGP.js */

var openpgp = require('openpgp'),
    mkdirp = require('mkdirp'),
    fs = require('fs')
;

/* Key Generation */

var generateKeyPair = function(options, callback, errorCallback) {
    openpgp.generateKeyPair(options).then(function(keypair) {
        callback(keypair);
    }).catch(errorCallback);
};

/* Key Decryption */

var decryptPrivateKey = function(privateKeyArmoredEncrypted, passphrase) {
    var privateKeyObject = openpgp.key.readArmored(privateKeyArmoredEncrypted).keys[0];
    privateKeyObject.decrypt(passphrase);
    return privateKeyObject;
};

/* Encryption */

var encryptMessage = function(publicKeyArmored, plaintextMessage, callback, errorCallback) {
    var publicKeyObjects = openpgp.key.readArmored(publicKeyArmored).keys;
    openpgp.encryptMessage(publicKeyObjects, plaintextMessage)
    .then(function(encryptedMessageArmored) {
        callback(encryptedMessageArmored);
    }).catch(errorCallback);
};

/* Decryption */

var decryptMessage = function(decryptedPrivateKeyObject, encryptedMessageArmored, callback, errorCallback) {
    var encryptedMessageObject = openpgp.message.readArmored(encryptedMessageArmored);
    openpgp.decryptMessage(decryptedPrivateKeyObject, encryptedMessageObject)
    .then(function(plaintext) {
        callback(plaintext);
    }).catch(errorCallback);
};

/* Signing */

var signMessage = function(decryptedPrivateKeyObject, plaintextMessage, callback, errorCallback) {
    openpgp.signClearMessage(decryptedPrivateKeyObject, plaintextMessage)
    .then(function(signedMessage) {
        callback(signedMessage);
    }).catch(errorCallback);
};

/* Verification */

var verifyMessage = function(publicKeyArmored, signedMessage, callback, errorCallback) {
    var publicKeyObject = openpgp.key.readArmored(publicKeyArmored).keys[0];
    var cleartextMessageObject = openpgp.cleartext.readArmored(signedMessage);
    openpgp.verifyClearSignedMessage(publicKeyObject, cleartextMessageObject)
    .then(function(result) {
        var validMessage = false;
        if ('signatures' in result) {
            var signatures = result['signatures'];
            if (signatures.length > 0) {
                var signature = signatures[0];
                if ('valid' in signature) {
                   validMessage = signature['valid'];
                }
            }
        }
        callback(validMessage);
    }).catch(errorCallback);
};

/* Utils */

var writeFile = function(pathname, data, fileLabel) {
    fs.writeFile(pathname, data, function(err) {
        if (!err) {
            console.log('writing ' + fileLabel + '...');
        } else {
            console.log(err);
        }
    });
};

/* Main */

var main = function() {
    var keyDirectory = 'keys',
        messageDirectory = 'messages',
        privateKeyFilename = 'privateKey.asc',
        publicKeyFilename = 'publicKey.asc',
        signedMessageFilename = 'signedMessage.asc',
        encryptedMessageFilename = 'encryptedMessage.asc',
        decryptedMessageFilename = 'decryptedMessage.asc'
    ;

    var options = {
        numBits: 4096,
        userId: 'Jon Smith <jon.smith@example.org>',
        passphrase: 'super long and hard to guess secret',
        plaintextMessage: 'Hello, World!'
    };

    var readFilePromise1 = new Promise(function(resolve, reject) {
        fs.readFile('keys/privateKey.asc', function(err, privateKeyArmored) {
            if (err) {
                reject(err);
            } else {
                resolve(privateKeyArmored);
            }
        });
    });

    var readFilePromise2 = new Promise(function(resolve, reject) {
        fs.readFile('keys/publicKey.asc', function(err, publicKeyArmored) {
            if (err) {
                reject(err);
            } else {
                resolve(publicKeyArmored);
            }
        });
    });

    var keypairPromise = new Promise(function(resolve, reject) {
        Promise.all([readFilePromise1, readFilePromise2])
        .then(function(responses) {
            var privateKeyArmored = responses[0],
                publicKeyArmored = responses[1];
            console.log('found public and private keypairs!');
            var keypair = {
                publicKeyArmored: publicKeyArmored.toString(),
                privateKeyArmored: privateKeyArmored.toString()
            };
            resolve(keypair);
        })
        .catch(function(errors) {
            console.log('generating keypair... (this may take a while)');
            generateKeyPair(options, function(keypair) {
                writeFile(keyDirectory + '/' + privateKeyFilename, keypair.privateKeyArmored, 'private key');
                writeFile(keyDirectory + '/' + publicKeyFilename, keypair.publicKeyArmored, 'public key');
                resolve(keypair);
            }, function(error) {
                reject(error);
            });
        });
    });

    keypairPromise.then(function(keypair) {
        var publicKeyArmored = keypair.publicKeyArmored,
            privateKeyArmored = keypair.privateKeyArmored,
            decryptedPrivateKeyObject = decryptPrivateKey(privateKeyArmored, options.passphrase);

        encryptMessage(publicKeyArmored, options.plaintextMessage, function(encryptedMessageArmored) {
            writeFile(messageDirectory + '/' + encryptedMessageFilename, encryptedMessageArmored, 'encrypted message');

            decryptMessage(decryptedPrivateKeyObject, encryptedMessageArmored, function(decryptedPlaintextMessage) {
                writeFile(messageDirectory + '/' + decryptedMessageFilename, decryptedPlaintextMessage, 'decrypted message');
            });
        }, function(error) {
            console.log(error);
        });
    });

    keypairPromise.then(function(keypair) {
        var publicKeyArmored = keypair.publicKeyArmored,
            privateKeyArmored = keypair.privateKeyArmored,
            decryptedPrivateKeyObject = decryptPrivateKey(privateKeyArmored, options.passphrase);

        signMessage(decryptedPrivateKeyObject, options.plaintextMessage, function(signedMessage) {
            writeFile(messageDirectory + '/' + signedMessageFilename, signedMessage, 'signed message');

            verifyMessage(publicKeyArmored, signedMessage, function(isValid) {
                console.log('verifying signed message... ' + isValid.toString() + '!');
            });
        }, function(error) {
            console.log(error); 
        });
    });

};

main();