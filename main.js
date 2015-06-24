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
        numBits: 2048,
        userId: 'Jon Smith <jon.smith@example.org>',
        passphrase: 'super long and hard to guess secret',
        plaintextMessage: 'Hello, World!'
    };

    var mkdirPromise = new Promise(function(resolve, reject) {
      mkdirp(keyDirectory, function(err) {
        if (err) {
          console.log(err);
          reject(err);
        } else {
          resolve();
        }
      });
    });

    var mkdirPromise2 = new Promise(function(resolve, reject) {
      mkdirp(messageDirectory, function(err) {
        if (err) {
          console.log(err);
          reject(err);
        } else {
          resolve();
        }
      });
    });

    var keypairPromise = new Promise(function(resolve, reject) {
        Promise.all([mkdirPromise, mkdirPromise2]).then(function() {
            generateKeyPair(options, function(keypair) {
                resolve(keypair);
            }, function(error) {
                reject(error);
            });
        });
    });

    keypairPromise.then(function(keypair) {
        var publicKeyArmored = keypair.publicKeyArmored;
        var privateKeyArmored = keypair.privateKeyArmored;
        var decryptedPrivateKeyObject = decryptPrivateKey(privateKeyArmored, options.passphrase);

        writeFile(keyDirectory + '/' + privateKeyFilename, privateKeyArmored, 'private key');
        writeFile(keyDirectory + '/' + publicKeyFilename, publicKeyArmored, 'public key');

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
        var publicKeyArmored = keypair.publicKeyArmored;
        var privateKeyArmored = keypair.privateKeyArmored;
        var decryptedPrivateKeyObject = decryptPrivateKey(privateKeyArmored, options.passphrase);

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