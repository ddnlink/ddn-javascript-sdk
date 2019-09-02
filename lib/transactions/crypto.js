var sha256 = require("fast-sha256");
var addressHelper = require('../address.js');
var options = require('../options');
var constants = require('../constants');
var trsTypes = require('../transaction-types');
var crypto = require('crypto');
var Mnemonic = require('bitcore-mnemonic');

if (typeof Buffer === "undefined") {
    Buffer = require("buffer/").Buffer;
}

var ByteBuffer = require("bytebuffer");
var bignum = require("@ddn/bignum-utils");
var nacl = require('tweetnacl')

var fixedPoint = Math.pow(10, 8);

function getSignatureBytes(signature) {
    var bb = new ByteBuffer(32, true);
    var publicKeyBuffer = new Buffer(signature.public_key, "hex");

    for (var i = 0; i < publicKeyBuffer.length; i++) {
        bb.writeByte(publicKeyBuffer[i]);
    }

    bb.flip();
    return new Uint8Array(bb.toArrayBuffer());
}

function toLocalBuffer(buf) {
    if (typeof window !== 'undefined') {
        return new Uint8Array(buf.toArrayBuffer())
    } else {
        return buf.toBuffer()
    }
}

function sha256Bytes(data) {
    return Buffer.from(sha256.hash(data))
}

function sha256Hex(data) {
    return Buffer.from(sha256.hash(data)).toString('hex')
}

function getTmnEvidenceBytes(tmnEvidence) {
    var bb = new ByteBuffer();

    try {
        bb.writeUTF8String(tmnEvidence.hash);
        bb.writeUTF8String(tmnEvidence.type);
        bb.writeUTF8String(tmnEvidence.dia_id);

        bb.flip();
    } catch (e) {
        throw Error(e.toString());
    }

    return toLocalBuffer(bb);
}

function getEvidenceBytes(evidence) {
    var bb = new ByteBuffer();

    try {
        bb.writeUTF8String(evidence.ipid);
        bb.writeUTF8String(evidence.title);
        bb.writeUTF8String(evidence.hash);
        bb.writeUTF8String(evidence.author);
        bb.writeUTF8String(evidence.url);
        bb.writeUTF8String(evidence.type);

        bb.flip();
    } catch (e) {
        throw Error(e.toString());
    }

    return toLocalBuffer(bb);
}

function getAobIssuerBytes(data) {
    var bb = new ByteBuffer();

    try {
        bb.writeUTF8String(data.name);
        bb.writeUTF8String(data.desc);

        bb.flip();
    } catch (e) {
        throw Error(e.toString());
    }

    return toLocalBuffer(bb);
}

function getAobAssetBytes(data) {
    let buffer = Buffer.concat([
        new Buffer(data.name, 'utf8'),
        new Buffer(data.desc, 'utf8'),
        new Buffer(data.maximum, 'utf8'),
        Buffer.from([data.precision || 0]),
        new Buffer(data.strategy || '', 'utf8'),
        Buffer.from([data.allow_writeoff || '0']),
        Buffer.from([data.allow_whitelist || '0']),
        Buffer.from([data.allow_blacklist || '0']),
    ]);
    const { strategy } = asset;
    if (strategy) {
        buffer = Buffer.concat([buffer]);
    }
    return buffer;
}

function getAobFlagsBytes(data) {
    var bb = new ByteBuffer();

    try {
        bb.writeUTF8String(data.currency);
        bb.writeInt(data.flag);
        bb.writeInt(data.flag_type);

        bb.flip();
    } catch (e) {
        throw Error(e.toString());
    }

    return toLocalBuffer(bb);
}

function getAobAclBytes(data) {
    var bb = new ByteBuffer();

    try {
        bb.writeString(data.currency);
        bb.writeString(data.operator);
        bb.writeByte(data.flag);
        if (data.list) {
            bb.writeString(data.list);
        }
        bb.flip();
    } catch (e) {
        throw Error(e.toString());
    }

    return bb.toBuffer()
}

function getAobIssueBytes(data) {
    var bb = new ByteBuffer();

    try {
        bb.writeUTF8String(data.currency);

        bb.flip();
    } catch (e) {
        throw Error(e.toString());
    }

    return toLocalBuffer(bb);
}

function getAobTransferBytes(data) {
    var bb = new ByteBuffer();

    try {
        bb.flip();
    } catch (e) {
        throw Error(e.toString());
    }

    return toLocalBuffer(bb);
}

function getDappBytes(dapp) {
    try {
        let buf = new Buffer([]);
        const nameBuf = new Buffer(dapp.name, 'utf8');
        buf = Buffer.concat([buf, nameBuf]);
        if (dapp.description) {
            const descriptionBuf = new Buffer(dapp.description, 'utf8');
            buf = Buffer.concat([buf, descriptionBuf]);
        }
        if (dapp.tags) {
            const tagsBuf = new Buffer(dapp.tags, 'utf8');
            buf = Buffer.concat([buf, tagsBuf]);
        }
        if (dapp.link) {
            buf = Buffer.concat([buf, new Buffer(dapp.link, 'utf8')]);
        }
        if (dapp.icon) {
            buf = Buffer.concat([buf, new Buffer(dapp.icon, 'utf8')]);
        }
        const bb = new ByteBuffer(1, true);
        bb.writeInt(dapp.type);
        bb.writeInt(dapp.category);
        if (dapp.delegates) {
            bb.writeString(dapp.delegates);
        }
        if (dapp.unlock_delegates || dapp.unlock_delegates === 0) {
            bb.writeInt(dapp.unlock_delegates);
        }
        bb.flip();
        buf = Buffer.concat([buf, bb.toBuffer()]);
       
    } catch (e) {
        throw Error(e.toString());
    }

    return buf;
}

function getDappInTransferBytes(transfer) {
    var buf = new Buffer([]);
    try {
        const dappId = new Buffer(transfer.dapp_id, 'utf8');
        if (transfer.currency !== this.tokenSetting.tokenName) {
            var currency = new Buffer(transfer.currency, 'utf8');
            const amount = new Buffer(transfer.amount, 'utf8');
            buf = Buffer.concat([buf, dappId, currency, amount]);
        } else {
            var currency = new Buffer(transfer.currency, 'utf8');
            buf = Buffer.concat([buf, dappId, currency]);
        }
    } catch (e) {
        throw Error(e.toString());
    }

    return buf;
}

function getDappOutTransferBytes(data) {
    var bb = new ByteBuffer();

    try {
        bb.writeUTF8String(data.dapp_id);
        bb.writeUTF8String(data.outtransaction_id);
        bb.writeUTF8String(data.amount);

        bb.flip();
    } catch (e) {
        throw Error(e.toString());
    }

    return toLocalBuffer(bb);
}

function getOrgBytes(data) {
    var bb = new ByteBuffer();

    try {
        bb.writeUTF8String(data.org_id.toLowerCase());
        bb.writeUTF8String(data.name ? data.name : '');
        bb.writeUTF8String(data.address ? data.address : '');
        bb.writeUTF8String(data.url ? data.url : '');
        bb.writeUTF8String(data.tags ? data.tags : '');
        bb.writeInt8(data.state);
        bb.flip();
    } catch (e) {
        throw Error(e.toString());
    }

    return bb.toBuffer();
}

function getExchangeBytes(data) {
    var bb = new ByteBuffer();

    try {
        bb.writeString(data.org_id.toLowerCase());
        bb.writeString(data.exchange_trs_id);
        bb.writeString(data.price);
        bb.writeInt8(data.state);
        bb.writeString(data.sender_address);
        bb.writeString(data.received_address);
        bb.flip();
    } catch (e) {
        throw Error(e.toString());
    }

    return bb.toBuffer();
}

function getContributionBytes(data) {
    var bb = new ByteBuffer();

    try {
        bb.writeUTF8String(data.title);
        bb.writeUTF8String(data.received_address);
        bb.writeUTF8String(data.sender_address);
        bb.writeUTF8String(data.price);
        bb.writeUTF8String(data.url);
        bb.flip();
    } catch (e) {
        throw Error(e.toString());
    }

    return bb.toBuffer();
}

function getConfirmationBytes(data) {
    var bb = new ByteBuffer();

    try {

        bb.flip();
    } catch (e) {
        throw Error(e.toString());
    }

    return toLocalBuffer(bb);
}

function getBytes(transaction, skipSignature, skipSecondSignature) {
    var assetSize = 0,
        assetBytes = null;

    switch (transaction.type) {
        case trsTypes.SIGNATURE: // Signature
            assetBytes = getSignatureBytes(transaction.asset.signature);
            break;

        case trsTypes.DELEGATE: // Delegate
            assetBytes = new Buffer(transaction.asset.delegate.username, "utf8");
            break;

        case trsTypes.VOTE: // Vote
            assetBytes = new Buffer(transaction.asset.vote.votes.join(""), "utf8");
            break;

        case trsTypes.MULTI: // Multi-Signature
            var keysgroupBuffer = new Buffer(transaction.asset.multisignature.keysgroup.join(""), "utf8");
            var bb = new ByteBuffer(1 + 1 + keysgroupBuffer.length, true);

            bb.writeByte(transaction.asset.multisignature.min);
            bb.writeByte(transaction.asset.multisignature.lifetime);

            for (var i = 0; i < keysgroupBuffer.length; i++) {
                bb.writeByte(keysgroupBuffer[i]);
            }

            bb.flip();

            assetBytes = bb.toBuffer();
            break;
        case trsTypes.TMN_EVIDENCE:
            assetBytes = getTmnEvidenceBytes(transaction.asset.tmnEvidence);
            break;
        case trsTypes.EVIDENCE:
            assetBytes = getEvidenceBytes(transaction.asset.evidence);
            break;
        case trsTypes.AOB_ISSUER:
            assetBytes = getAobIssuerBytes(transaction.asset.aobIssuer);
            break;
        case trsTypes.AOB_ASSET:
            assetBytes = getAobAssetBytes(transaction.asset.aobAsset);
            break;
        case trsTypes.AOB_FLAGS:
            assetBytes = getAobFlagsBytes(transaction.asset.aobFlags);
            break; 
        case trsTypes.AOB_ACL:
            assetBytes = getAobAclBytes(transaction.asset.aobAcl);
            break;   
        case trsTypes.AOB_ISSUE:
            assetBytes = getAobIssueBytes(transaction.asset.aobIssue);
            break; 
        case trsTypes.AOB_TRANSFER:
            assetBytes = getAobTransferBytes(transaction.asset.aobTransfer);
            break; 
        case trsTypes.DAPP:
            assetBytes = getDappBytes(transaction.asset.Dapp);
            break; 
        case trsTypes.DAPP_IN_TRANSFER:
            assetBytes = getDappInTransferBytes(transaction.asset.InTransfer);
            break; 
        case trsTypes.DAPP_OUT_TRANSFER:
            assetBytes = getDappOutTransferBytes(transaction.asset.OutTransfer);
            break; 
        case trsTypes.ORG:
            assetBytes = getOrgBytes(transaction.asset.org);
            break; 
        case trsTypes.EXCHANGE:
            assetBytes = getExchangeBytes(transaction.asset.exchange);
            break;
        case trsTypes.CONTRIBUTION:
            assetBytes = getContributionBytes(transaction.asset.contribution);
            break;
        case trsTypes.CONFIRMATION:
            assetBytes = getConfirmationBytes(transaction.asset.confirmation);
            break;
        default:
            // fix 这里应该是一个报错！没有对应的交易类型
            throw Error('交易类型错误');
          break;
    }

    if (transaction.__assetBytes__) {
        assetBytes = transaction.__assetBytes__;
    }
    if (assetBytes) assetSize = assetBytes.length

    var bb = new ByteBuffer(1, true);
    bb.writeByte(transaction.type); // +1
    bb.writeInt(transaction.timestamp); // +4
    bb.writeString(transaction.nethash); // +8

    // +32
    var senderPublicKeyBuffer = new Buffer(transaction.sender_public_key, "hex");
    // var senderPublicKeyBuffer = new Buffer(transaction.senderPublicKey, "hex");
    for (var i = 0; i < senderPublicKeyBuffer.length; i++) {
        bb.writeByte(senderPublicKeyBuffer[i]);
    }

    // +32
    if (transaction.requester_public_key) { //wxm block database
        var requesterPublicKey = new Buffer(transaction.requester_public_key, "hex"); //wxm block database

        for (var i = 0; i < requesterPublicKey.length; i++) {
            bb.writeByte(requesterPublicKey[i]);
        }
    }

    // +8
    if (transaction.recipient_id) {
        bb.writeString(transaction.recipient_id);
    } else {
        for (var i = 0; i < 8; i++) {
            bb.writeByte(0);
        }
    }

    // +8
    bb.writeString(transaction.amount);

    // +64
    if (transaction.message) bb.writeString(transaction.message)

    // +64
    if (transaction.args) {
        var args = transaction.args
        for (var i = 0; i < args.length; ++i) {
            bb.writeString(args[i])
        }
    }

    if (assetSize > 0) {
        for (var i = 0; i < assetSize; i++) {
            bb.writeByte(assetBytes[i]);
        }
    }

    if (!skipSignature && transaction.signature) {
        var signatureBuffer = new Buffer(transaction.signature, "hex");
        for (var i = 0; i < signatureBuffer.length; i++) {
            bb.writeByte(signatureBuffer[i]);
        }
    }

    if (!skipSecondSignature && transaction.sign_signature) {  //wxm block database
        var signSignatureBuffer = new Buffer(transaction.sign_signature, "hex"); //wxm block database
        for (var i = 0; i < signSignatureBuffer.length; i++) {
            bb.writeByte(signSignatureBuffer[i]);
        }
    }

    bb.flip();

    // competifined browser
    var arrayBuffer = new Uint8Array(bb.toArrayBuffer());
    var buffer = [];

    for (var i = 0; i < arrayBuffer.length; i++) {
        buffer[i] = arrayBuffer[i];
    }

    return new Buffer(buffer);
    // return bb.toBuffer();
}

function getId(transaction) {
    return sha256Hex(getBytes(transaction))
}

function getHash(transaction, skipSignature, skipSecondSignature) {
    return sha256Bytes(getBytes(transaction, skipSignature, skipSecondSignature))
}

function getFee(transaction) {
    switch (transaction.type) {
        case trsTypes.SEND: // Normal
            return bignum.multiply(0.1, fixedPoint);
            break;
        case trsTypes.SIGNATURE: // Signature
            return bignum.multiply(100, fixedPoint);
            break;
        case trsTypes.DELEGATE: // Delegate
            return bignum.multiply(10000, fixedPoint);
            break;
        case trsTypes.VOTE: // Vote
            return bignum.new(fixedPoint);
            break;
        case trsTypes.TMN_EVIDENCE:
            return "0";
            break;
        default: {
            var fee = constants.fees.send;
            return fee;
        }
    }
}

function sign(transaction, keys) {
    var hash = getHash(transaction, true, true);
    var signature = nacl.sign.detached(hash, new Buffer(keys.private_key, "hex"));

    if (!transaction.signature) {
        transaction.signature = new Buffer(signature).toString("hex");
    } else {
        return new Buffer(signature).toString("hex");
    }
}

function secondSign(transaction, keys) {
    var hash = getHash(transaction);
    var signature = nacl.sign.detached(hash, new Buffer(keys.private_key, "hex"));
    transaction.sign_signature = new Buffer(signature).toString("hex")    //wxm block database
}

function signBytes(bytes, keys) {
    var hash = sha256Bytes(new Buffer(bytes, 'hex'))
    var signature = nacl.sign.detached(hash, new Buffer(keys.private_key, "hex"));
    return new Buffer(signature).toString("hex");
}

function verify(transaction) {
    var remove = 64;

    if (transaction.signSignature) {
        remove = 128;
    }

    var bytes = getBytes(transaction);
    var data2 = new Buffer(bytes.length - remove);

    for (var i = 0; i < data2.length; i++) {
        data2[i] = bytes[i];
    }

    var hash = sha256Bytes(data2)

    var signatureBuffer = new Buffer(transaction.signature, "hex");
    var senderPublicKeyBuffer = new Buffer(transaction.sender_public_key, "hex");
    var res = nacl.sign.detached.verify(hash, signatureBuffer, senderPublicKeyBuffer);

    return res;
}

function verifySecondSignature(transaction, public_key) {
    var bytes = getBytes(transaction);
    var data2 = new Buffer(bytes.length - 64);

    for (var i = 0; i < data2.length; i++) {
        data2[i] = bytes[i];
    }

    var hash = sha256Bytes(data2)

    var signSignatureBuffer = new Buffer(transaction.signSignature, "hex");
    var publicKeyBuffer = new Buffer(public_key, "hex");
    var res = nacl.sign.detached.verify(hash, signSignatureBuffer, publicKeyBuffer);

    return res;
}

function verifyBytes(bytes, signature, public_key) {
    var hash = sha256Bytes(new Buffer(bytes, 'hex'))
    var signatureBuffer = new Buffer(signature, "hex");
    var publicKeyBuffer = new Buffer(public_key, "hex");
    var res = nacl.sign.detached.verify(hash, signatureBuffer, publicKeyBuffer);
    return res
}

// 根据助记词生成密钥对
function getKeys(secret) {
    var hash = sha256Bytes(new Buffer(secret));
    var keypair = nacl.sign.keyPair.fromSeed(hash);

    return {
        public_key: new Buffer(keypair.publicKey).toString("hex"),
        private_key: new Buffer(keypair.secretKey).toString("hex")
    }
}

//根据公钥生成账户地址
function getAddress(public_key) {
    return addressHelper.generateBase58CheckAddress(public_key)
}

//生成助记词
function generatePhasekey()
{
    var secret = new Mnemonic(128).toString();
    return secret;
}

function generateHash(content)
{
    var md5 = crypto.createHash('md5');
    var result = md5.update(content).digest('hex');
    return result;
}

module.exports = {
    getBytes: getBytes,
    getHash: getHash,
    getId: getId,
    getFee: getFee,
    sign: sign,
    secondSign: secondSign,
    getKeys: getKeys,
    getAddress: getAddress,
    verify: verify,
    verifySecondSignature: verifySecondSignature,
    fixedPoint: fixedPoint,
    signBytes: signBytes,
    toLocalBuffer: toLocalBuffer,
    verifyBytes: verifyBytes,
    isAddress: addressHelper.isAddress,
    isBase58CheckAddress: addressHelper.isBase58CheckAddress,
    generatePhasekey: generatePhasekey,
    generateHash: generateHash
}