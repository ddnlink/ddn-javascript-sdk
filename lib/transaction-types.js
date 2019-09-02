/*---------------------------------------------------------------------------------------------
 *  Created by imfly on Wed Mar 14 2017 16:21:58
 *
 *  Copyright (c) 2017 DDN.link. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

module.exports = {
  // base 0-19
  SEND: 0, // TRANSFER
  SIGNATURE: 1, // SETUP SECOND_PASSWORD
  DELEGATE: 2, // SECOND_PASSWORD
  VOTE: 3, // VOTE FOR DELEGATE
  MULTI: 4, // MULTISIGNATURE
  DAPP: 5, // DAPP REGISTER
  IN_TRANSFER: 6, // DAPP DEPOSIT
  OUT_TRANSFER: 7, // DAPP WITHDRAW

  MULTITRANSFER: 8,
  USERINFO: 9,

  // javascript版扩展资产部分交易类型 - 以下内容
  // 存证
  EVIDENCE: 10,
  
  // AOB-ASSET
  AOB_ISSUER: 60, // AOB ISSUER REGISTER
  AOB_ASSET: 61, // AOB ASSET REGISTER
  AOB_FLAGS: 62, // AOB FLAGS UPDATE
  AOB_ACL: 63, // AOB ACL UPDATE
  AOB_ISSUE: 64, // AOB ISSUE
  AOB_TRANSFER: 65, // AOB TRANSFER

  // Dapp
  DAPP: 11,
  DAPP_IN_TRANSFER: 12,
  DAPP_OUT_TRANSFER: 13,

  //DAO
  ORG: 40,
  EXCHANGE: 41,
  CONTRIBUTION: 42,
  CONFIRMATION: 43,

  LOCK: 100 // ACCOUNT LOCK
}
