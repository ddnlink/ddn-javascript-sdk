var crypto = require('./crypto.js');
var constants = require('../constants.js');
var slots = require('../time/slots.js');
var options = require('../options');
var typeConfig = {
  10: 'eviendt',
  60: 'aobIssuer',
  61: 'aobAsset',
  62: 'aobFlags',
  63: 'aobAcl',
  64: 'aobIssue',
  65: 'aobTransfer',
  11: 'dapp',
  12: 'inTransfer',
  13: 'outTransfer',
  40: 'org',
  41: 'exchange',
  42: 'contribution',
  43: 'confirmation',
};

function createPluginAsset(trsType, assetInfo, secret, secondSecret) {
    var keys = crypto.getKeys(secret);
    // var fee = assetInfo.fee || constants.fees.org;
    delete assetInfo.fee;
    var transaction = {
        type: trsType,
        nethash: options.get('nethash'),
        amount: assetInfo.amount ? assetInfo.amount + "" : "0",
        recipient_id: assetInfo.recipient_id ? assetInfo.recipient_id : null,
        sender_public_key: keys.public_key,
        timestamp: slots.getTime() - options.get('clientDriftSeconds'),
        message: assetInfo.message ? assetInfo.message + "" : null,
        asset: {}
    };
    delete assetInfo.amount;
    delete assetInfo.recipient_id;
    delete assetInfo.message;
    if (assetInfo.aobAmount) {
        assetInfo.amount = assetInfo.aobAmount;
        delete assetInfo.aobAmount;
    }
    // fix 这个是创建二级密码使用的 这个条件是否应该再次检查一下或优化一下
    if (assetInfo.secondSecret && trsType === 1) {
        var secondSecretKeys = crypto.getKeys(assetInfo.secondSecret);
        assetInfo = { public_key: secondSecretKeys.public_key };
        delete transaction.message;
    }
    var assetJsonName = typeConfig[trsType];
    transaction.asset[assetJsonName] = assetInfo;
    if (assetInfo.fee) {
        transaction.fee = assetInfo.fee;
    } else {
        transaction.fee = await crypto.getFee(transaction);
    }
    await crypto.sign(transaction, keys);
    if (secondSecret) {
        var secondKeys = crypto.getKeys(secondSecret);
        await crypto.secondSign(transaction, secondKeys);
    }
    return transaction;
}
module.exports = {
    createPluginAsset: createPluginAsset
};