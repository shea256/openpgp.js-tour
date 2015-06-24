/* OpenPGP.js Tutorial */

var openpgp = require('openpgp');

/* Key Generation */

var generateKeyPair = function(options, callback, errorCallback) {
	openpgp.generateKeyPair(options).then(function(keypair) {
	    privateKeyArmored = keypair.privateKeyArmored;
	    publicKeyArmored = keypair.publicKeyArmored;

	    callback(privateKeyArmored, publicKeyArmored);
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
	openpgp.decryptMessage(privateKeyObject, encryptedMessageObject)
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

var verifyMessage = function(publicKeyArmored, signedMessage, callback, errorCallback) {
	var publicKeyObjects = openpgp.key.readArmored(publicKeyArmored).keys;
	var cleartextMessageObject = openpgp.cleartext.CleartextMessage(signedMessage);
	openpgp.verifyClearSignedMessage(publicKeyObjects, cleartextMessageObject)
	.then(function(result) {
		if ('valid' in result) {
			callback(true);
		} else {
			callback(false);
		}
	}).catch(errorCallback);
};

var main = function() {
	var options = {
		numBits: 2048,
		userId: 'Jon Smith <jon.smith@example.org>',
	    passphrase: 'super long and hard to guess secret',
		plaintextMessage: 'Hello, World!'
	};

	generateKeyPair(options, function(privateKeyArmored, publicKeyArmored) {
		console.log(privateKeyArmored);
		console.log(publicKeyArmored);

		var decryptedPrivateKeyObject = decryptPrivateKey(privateKeyArmored, options.passphrase);

		encryptMessage(publicKeyArmored, options.plaintextMessage, function(encryptedMessageArmored) {
			console.log(encryptedMessageArmored);
			decryptMessage(decryptedPrivateKeyObject, encryptedMessageArmored, function(decryptedPlaintextMessage) {
				console.log(decryptedPlaintextMessage);
			});
		});

		signMessage(decryptedPrivateKeyObject, options.plaintextMessage, function(signedMessage) {
			console.log(signedMessage);
			verifyMessage(signedMessage, publicKeyArmored, function(isValid) {
				console.log(isValid);
			});
		}, function(error) {
			console.log(error);	
		});
	});
};

main();