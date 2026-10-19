// Generates sdk-shield.json: shield fixtures produced by these pinned Railgun
// SDK package versions. Every key below is synthetic. Never supply a real
// wallet to this script, and never fund the derived addresses.
//   @railgun-community/engine        9.8.0
//   @railgun-community/wallet        11.2.0
//   @railgun-community/shared-models 8.2.1
//   ethers                           6.14.3
//
// Pass a directory whose node_modules holds exactly those versions. Railway
// Wallet v5.26.1's desktop checkout (commit
// e9398a1ccf94ff016062592fc310a8a697d94f2b, `yarn install --immutable` in
// desktop/) locks them. From this workspace's root run
//   node crates/core/tests/fixtures/generate-sdk-shield.cjs <dir>
// and compare stdout with sdk-shield.json. Package versions and the SHA-256 of
// every reference source used below are checked before loading.
//
// The SDK draws the note random and both AES IVs from a CSPRNG. This script
// passes a fixed note random and replaces `AES.getRandomIV` with a queue of
// fixed IVs, consumed in the order `ShieldNote.serialize` uses them: the
// AES-GCM note-random IV first, then the AES-CTR receiver IV. The native
// transaction uses the SDK's own `createShieldBaseTokenTransaction7702` with a
// stub provider that reports a fresh account: no code, account nonce 0.
const path = require('node:path');
const fs = require('node:fs');
const { createHash } = require('node:crypto');
const assert = require('node:assert/strict');

const root = process.argv[2];
if (!root) throw new Error('Provide a directory with the pinned SDK packages installed');
const modules = path.join(path.resolve(root), 'node_modules');
const versions = {
  '@railgun-community/engine': '9.8.0',
  '@railgun-community/wallet': '11.2.0',
  '@railgun-community/shared-models': '8.2.1',
  ethers: '6.14.3',
};
for (const [name, version] of Object.entries(versions)) {
  const manifest = JSON.parse(fs.readFileSync(path.join(modules, name, 'package.json')));
  assert.equal(manifest.version, version, name);
}
const checksums = {
  '@railgun-community/engine/dist/note/shield-note.js': '3cb7529c38b9cd6b2674c6b008b531e437fdefba8508a7eb8768b2f4d95325fd',
  '@railgun-community/engine/dist/note/erc20/shield-note-erc20.js': 'cc155beadc0a3bb6e624c4f7db6aa0b480b80b1e87c415824794a63b8a7fd0e2',
  '@railgun-community/engine/dist/utils/encryption/aes.js': '20970f5e053a96c2f0a3d5de1ec9bf772284a405525a82db1be0a63fd25a13cb',
  '@railgun-community/engine/dist/utils/keys-utils.js': '2a30e83c5a4dfd9c7f2f29b3d0135fa86f081084f42fd961c613b861a26347cc',
  '@railgun-community/engine/dist/contracts/relay-adapt/relay-adapt-7702-helper.js': 'a29f24fab7107c3ce7287a963cf385f084a7debebb6294e859ba84444584f864',
  '@railgun-community/engine/dist/transaction/relay-adapt-7702-signature.js': 'e800cb7606bcb739b8dcd25979bbb835be9e4d184bf4eb795355206bfa62fef7',
  '@railgun-community/engine/dist/transaction/eip7702.js': '2965f57f46b06ad49335f953765a7b615f23cc04a6e66db888e34fe43b69c1fd',
  '@railgun-community/wallet/dist/services/transactions/tx-shield-base-token-7702.js': 'c72753e7d6176d7572a1f91ff4088279de1a28d0fa7e71e7b50771fbce039615',
  '@railgun-community/wallet/dist/services/railgun/wallets/relay-adapt-7702-execution.js': '1dec3c702f28a984061013ba9dee86d7506c6f19654e29c6848a230a666bcfa0',
  '@railgun-community/shared-models/dist/models/network-config.js': '6cc3aaad09a1caab876dc453ebfe2407f8e9849df3fbb17e3faed93a769549f5',
};
for (const [file, digest] of Object.entries(checksums)) {
  const source = fs.readFileSync(path.join(modules, file));
  assert.equal(createHash('sha256').update(source).digest('hex'), digest, file);
}
const load = (file) => require(path.join(modules, file));
const engine = load('@railgun-community/engine');
const models = load('@railgun-community/shared-models');
const ethers = load('ethers');
const { AES } = load('@railgun-community/engine/dist/utils/encryption/aes.js');
const native = load('@railgun-community/wallet/dist/services/transactions/tx-shield-base-token-7702.js');
const { EphemeralAccount } = load('@railgun-community/wallet/dist/services/railgun/wallets/ephemeral-account.js');

const ivs = [];
AES.getRandomIV = () => {
  assert.ok(ivs.length > 0, 'unexpected AES IV request');
  return ivs.shift();
};

const shieldSignerKey = `0x${'5e'.repeat(32)}`;
const viewingPrivateKey = `0x${'22'.repeat(32)}`;
const masterPublicKey = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefn;
const random = '0f1e2d3c4b5a69788796a5b4c3d2e1f0';
const gcmIv = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';
const ctrIv = 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf';
const amount = 1234567890123456789n;
const erc20Token = `0x${'c0'.repeat(20)}`;
const executorKey = `0x${'77'.repeat(32)}`;
const networks = [
  models.NetworkName.Ethereum,
  models.NetworkName.BNBChain,
  models.NetworkName.Polygon,
  models.NetworkName.Arbitrum,
];

const railgun = new ethers.Interface(engine.ABIRailgunSmartWallet);
const toJson = (value) => JSON.parse(JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item));

async function shieldRequest(shieldPrivateKey, viewingPublicKey, token) {
  ivs.push(gcmIv, ctrIv);
  const note = new engine.ShieldNoteERC20(masterPublicKey, random, amount, token);
  const request = await note.serialize(shieldPrivateKey, viewingPublicKey);
  assert.equal(ivs.length, 0, 'shield serialization must use both fixed IVs');
  return request;
}

async function main() {
  const shieldSigner = new ethers.Wallet(shieldSignerKey);
  const shieldPrivateKey = ethers.keccak256(await shieldSigner.signMessage(engine.ShieldNote.getShieldPrivateKeySignatureMessage()));
  const viewingPublicKey = await engine.getPublicViewingKey(ethers.getBytes(viewingPrivateKey));
  const shieldKeyBytes = ethers.getBytes(shieldPrivateKey);

  const erc20 = await shieldRequest(shieldKeyBytes, viewingPublicKey, erc20Token);
  const provider = {
    getTransactionCount: async () => 0,
    getCode: async () => '0x',
  };
  const executor = new EphemeralAccount(new ethers.Wallet(executorKey, provider));
  const nativeVectors = [];
  for (const networkName of networks) {
    const network = models.NETWORK_CONFIG[networkName];
    const request = await shieldRequest(shieldKeyBytes, viewingPublicKey, network.baseToken.wrappedAddress);
    const transaction = await native.createShieldBaseTokenTransaction7702(
      models.TXIDVersion.V2_PoseidonMerkle, networkName, request, executor);
    assert.equal(transaction.type, 4);
    assert.equal(transaction.authorizationList.length, 1);
    const authorization = transaction.authorizationList[0];
    nativeVectors.push({
      chainId: network.chain.id,
      proxy: network.proxyContract,
      wrappedToken: network.baseToken.wrappedAddress,
      delegate: network.relayAdapt7702Contract,
      shieldCalldata: railgun.encodeFunctionData('shield', [[request]]),
      transaction: {
        type: transaction.type,
        to: transaction.to,
        value: transaction.value,
        data: transaction.data,
        authorization: {
          address: authorization.address,
          chainId: authorization.chainId,
          nonce: authorization.nonce,
          signature: { yParity: authorization.signature.yParity, r: authorization.signature.r, s: authorization.signature.s },
        },
      },
    });
  }

  const fixture = {
    reference: {
      engine: versions['@railgun-community/engine'],
      wallet: versions['@railgun-community/wallet'],
      sharedModels: versions['@railgun-community/shared-models'],
      ethers: versions.ethers,
    },
    inputs: {
      shieldSignerKey, viewingPrivateKey, masterPublicKey, random, gcmIv, ctrIv, amount, executorKey,
    },
    executorAddress: executor.address,
    shieldPrivateKey,
    viewingPublicKey: ethers.hexlify(viewingPublicKey),
    erc20: { token: erc20Token, request: erc20, shieldCalldata: railgun.encodeFunctionData('shield', [[erc20]]) },
    native: nativeVectors,
  };
  process.stdout.write(`${JSON.stringify(toJson(fixture), null, 2)}\n`);
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
