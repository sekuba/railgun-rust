use alloy::primitives::{Address, FixedBytes, U256, Uint, keccak256};
use alloy::sol_types::SolCall;

use crate::contracts::railgun::{
    CommitmentPreimage, ShieldCiphertext, ShieldRequest, TokenData, approveCall, shieldCall,
};
use crate::crypto::aes_gcm::{AesGcmError, encrypt_in_place_with_iv};
use crate::crypto::shared_key::{SharedKeyError, shared_symmetric_key};
use crate::notes::Note;

use ctr::cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::SigningKey;
use getrandom::fill;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShieldError {
    #[error("random generation failed")]
    RandomFailed,
    #[error("shared key derivation failed: {0}")]
    SharedKey(#[from] SharedKeyError),
    #[error("encryption failed: {0}")]
    Encrypt(#[from] AesGcmError),
    #[error("invalid EVM private key")]
    InvalidPrivateKey,
    #[error("ECDSA signing failed")]
    SigningFailed,
}

/// Railgun fee denominator, `BASIS_POINTS` in `RailgunLogic`.
const FEE_BASIS_POINTS: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ShieldFeeError {
    #[error("minimum shielded amount must be nonzero")]
    ZeroMinimum,
    #[error("shield fee must be below 10000 basis points")]
    FeeTooHigh,
    #[error("required shield amount exceeds the uint120 note value")]
    Overflow,
}

/// Smallest amount to shield so the note receives at least `min_net` after the
/// shield fee.
///
/// Railgun's inclusive `getFee` leaves `amount - floor(amount * fee_bp / 10000)`
/// in the note, which rises by at most 1 per unit of `amount`. The smallest
/// sufficient amount is therefore
/// `floor((min_net - 1) * 10000 / (10000 - fee_bp)) + 1`.
///
/// A zero `min_net` is rejected: the result is used as the executor's exact
/// transfer guard, and its transfer helper treats 0 as the full balance.
pub fn min_shield_amount(min_net: U256, fee_bp: U256) -> Result<U256, ShieldFeeError> {
    if min_net.is_zero() {
        return Err(ShieldFeeError::ZeroMinimum);
    }
    let basis = U256::from(FEE_BASIS_POINTS);
    if fee_bp >= basis {
        return Err(ShieldFeeError::FeeTooHigh);
    }
    let amount = (min_net - U256::ONE)
        .checked_mul(basis)
        .ok_or(ShieldFeeError::Overflow)?
        / (basis - fee_bp)
        + U256::ONE;
    if amount.bit_len() > 120 {
        return Err(ShieldFeeError::Overflow);
    }
    Ok(amount)
}

/// Build ABI-encoded calldata for `shield(ShieldRequest[])`.
///
/// `shield_private_key` is the 32-byte key derived from `keccak256(evm_sign("RAILGUN_SHIELD"))`.
pub fn build_shield_calldata(
    master_public_key: U256,
    viewing_public_key: &[u8; 32],
    token_address: Address,
    amount: U256,
    shield_private_key: &[u8; 32],
) -> Result<Vec<u8>, ShieldError> {
    let request = build_shield_request(
        master_public_key,
        viewing_public_key,
        TokenData::erc20(token_address),
        Uint::<120, 2>::from(amount),
        shield_private_key,
    )?;
    Ok(shieldCall {
        _shieldRequests: vec![request],
    }
    .abi_encode())
}

/// Build an encrypted shield request for the supplied protocol token and value.
///
/// Callers select the token standards supported by their execution route. Keeping
/// the typed request also lets them track its commitment before transaction handoff.
pub fn build_shield_request(
    master_public_key: U256,
    viewing_public_key: &[u8; 32],
    token: TokenData,
    value: Uint<120, 2>,
    shield_private_key: &[u8; 32],
) -> Result<ShieldRequest, ShieldError> {
    let mut random = [0u8; 16];
    let mut gcm_iv = [0u8; 16];
    let mut ctr_iv = [0u8; 16];
    fill(&mut random).map_err(|_| ShieldError::RandomFailed)?;
    fill(&mut gcm_iv).map_err(|_| ShieldError::RandomFailed)?;
    fill(&mut ctr_iv).map_err(|_| ShieldError::RandomFailed)?;
    build_shield_request_with(
        ShieldRandomness {
            random,
            gcm_iv,
            ctr_iv,
        },
        master_public_key,
        viewing_public_key,
        token,
        value,
        shield_private_key,
    )
}

/// Randomness drawn for one shield request; fixed only by reference fixtures.
#[derive(Clone, Copy)]
struct ShieldRandomness {
    random: [u8; 16],
    gcm_iv: [u8; 16],
    ctr_iv: [u8; 16],
}

fn build_shield_request_with(
    randomness: ShieldRandomness,
    master_public_key: U256,
    viewing_public_key: &[u8; 32],
    token: TokenData,
    value: Uint<120, 2>,
    shield_private_key: &[u8; 32],
) -> Result<ShieldRequest, ShieldError> {
    let ShieldRandomness {
        random,
        gcm_iv,
        ctr_iv,
    } = randomness;
    let npk = Note::npk_for(master_public_key, random);

    let preimage = CommitmentPreimage {
        npk: FixedBytes::from(npk.to_be_bytes::<32>()),
        token,
        value,
    };

    let ciphertext = encrypt_shield_random(
        random,
        gcm_iv,
        ctr_iv,
        shield_private_key,
        viewing_public_key,
    )?;

    Ok(ShieldRequest {
        preimage,
        ciphertext,
    })
}

/// Build ABI-encoded calldata for ERC-20 `approve(spender, amount)`.
#[must_use]
pub fn build_approve_calldata(spender: Address, amount: U256) -> Vec<u8> {
    approveCall { spender, amount }.abi_encode()
}

/// Derive `shieldPrivateKey` from an EVM private key.
///
/// Signs the fixed message `"RAILGUN_SHIELD"` using EIP-191 personal sign,
/// then returns `keccak256(signature)`.
pub fn derive_shield_private_key(evm_private_key: &[u8; 32]) -> Result<[u8; 32], ShieldError> {
    let msg = b"RAILGUN_SHIELD";

    // EIP-191 personal sign hash: keccak256("\x19Ethereum Signed Message:\n" + len + msg)
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    let mut hash_input = Vec::with_capacity(prefix.len() + msg.len());
    hash_input.extend_from_slice(prefix.as_bytes());
    hash_input.extend_from_slice(msg);
    let msg_hash = keccak256(&hash_input);

    // secp256k1 ECDSA sign
    let signing_key = k256::ecdsa::SigningKey::from_bytes(evm_private_key.into())
        .map_err(|_| ShieldError::InvalidPrivateKey)?;
    let (signature, recovery_id) = signing_key.sign_prehash_recoverable(msg_hash.as_ref());

    // 65-byte signature: r (32) + s (32) + v (1)
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&signature.to_bytes());
    sig_bytes[64] = recovery_id.to_byte() + 27;

    Ok(keccak256(sig_bytes).0)
}

fn encrypt_shield_random(
    random: [u8; 16],
    gcm_iv: [u8; 16],
    ctr_iv: [u8; 16],
    shield_private_key: &[u8; 32],
    viewing_public_key: &[u8; 32],
) -> Result<ShieldCiphertext, ShieldError> {
    // Derive the ed25519 public key from shield_private_key to use as shieldKey
    let shield_public_key = SigningKey::from_bytes(shield_private_key)
        .verifying_key()
        .to_bytes();

    // Compute shared symmetric key via ECDH
    let shared_key = shared_symmetric_key(shield_private_key, viewing_public_key)?;

    // Encrypt the 16-byte random
    let mut buffer = random;
    let iv_tag = encrypt_in_place_with_iv(&shared_key, gcm_iv, &mut buffer)?;

    // Encrypt the receiver viewing key to the shielder, as the Railgun SDK engine does:
    // AES-256-CTR keyed directly by shield_private_key.
    let mut encrypted_receiver = *viewing_public_key;
    ctr::Ctr128BE::<aes::Aes256>::new(shield_private_key.into(), &ctr_iv.into())
        .apply_keystream(&mut encrypted_receiver);

    // Pack into ShieldCiphertext: encryptedBundle[0] = gcm iv||tag,
    // encryptedBundle[1] = encrypted random||ctr iv, encryptedBundle[2] = encrypted receiver
    let mut bundle1 = [0u8; 32];
    bundle1[..16].copy_from_slice(&buffer);
    bundle1[16..].copy_from_slice(&ctr_iv);
    let bundle = [
        FixedBytes::from(iv_tag),
        FixedBytes::from(bundle1),
        FixedBytes::from(encrypted_receiver),
    ];

    Ok(ShieldCiphertext {
        encryptedBundle: bundle,
        shieldKey: FixedBytes::from(shield_public_key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn sdk_fixture() -> Value {
        serde_json::from_str(include_str!("../../tests/fixtures/sdk-shield.json"))
            .expect("SDK shield fixture")
    }

    fn fixture_bytes<const N: usize>(value: &Value) -> [u8; N] {
        let hex = value.as_str().expect("hex string");
        alloy::hex::decode(hex)
            .expect("hex bytes")
            .try_into()
            .expect("fixed length")
    }

    #[test]
    fn shield_request_matches_sdk() {
        let fixture = sdk_fixture();
        let inputs = &fixture["inputs"];
        let shield_private_key =
            derive_shield_private_key(&fixture_bytes(&inputs["shieldSignerKey"]))
                .expect("shield key");
        assert_eq!(
            shield_private_key,
            fixture_bytes::<32>(&fixture["shieldPrivateKey"])
        );
        let master_public_key: U256 = inputs["masterPublicKey"].as_str().unwrap().parse().unwrap();
        let value: Uint<120, 2> = inputs["amount"].as_str().unwrap().parse().unwrap();
        let token: Address = fixture["erc20"]["token"].as_str().unwrap().parse().unwrap();
        let request = build_shield_request_with(
            ShieldRandomness {
                random: fixture_bytes(&inputs["random"]),
                gcm_iv: fixture_bytes(&inputs["gcmIv"]),
                ctr_iv: fixture_bytes(&inputs["ctrIv"]),
            },
            master_public_key,
            &fixture_bytes(&fixture["viewingPublicKey"]),
            TokenData::erc20(token),
            value,
            &shield_private_key,
        )
        .expect("shield request");
        let expected: alloy::primitives::Bytes = fixture["erc20"]["shieldCalldata"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            alloy::primitives::Bytes::from(
                shieldCall {
                    _shieldRequests: vec![request.clone()],
                }
                .abi_encode()
            ),
            expected
        );

        // The receiver recovers the note random with its viewing key.
        let [iv_tag, random_and_ctr_iv, encrypted_receiver] =
            request.ciphertext.encryptedBundle.map(|word| word.0);
        let shared_key = shared_symmetric_key(
            &fixture_bytes(&inputs["viewingPrivateKey"]),
            &request.ciphertext.shieldKey.0,
        )
        .expect("receiver shared key");
        let (iv, tag) = crate::crypto::aes_gcm::split_iv_tag(iv_tag);
        let mut random: [u8; 16] = random_and_ctr_iv[..16].try_into().unwrap();
        crate::crypto::aes_gcm::decrypt_in_place_16b_iv(&shared_key, &iv, &tag, &mut random)
            .expect("receiver decrypts random");
        assert_eq!(random, fixture_bytes::<16>(&inputs["random"]));

        // The shielder recovers the receiver viewing key with its shield key.
        let mut receiver = encrypted_receiver;
        let ctr_iv: [u8; 16] = random_and_ctr_iv[16..].try_into().unwrap();
        ctr::Ctr128BE::<aes::Aes256>::new(&shield_private_key.into(), &ctr_iv.into())
            .apply_keystream(&mut receiver);
        assert_eq!(receiver, fixture_bytes::<32>(&fixture["viewingPublicKey"]));
    }

    // Note value left by `RailgunLogic.getFee(amount, true, fee_bp)`.
    fn net(amount: U256, fee_bp: u64) -> U256 {
        amount - amount * U256::from(fee_bp) / U256::from(FEE_BASIS_POINTS)
    }

    fn assert_minimal(amount: U256, min_net: U256, fee_bp: u64) {
        assert!(
            net(amount, fee_bp) >= min_net,
            "{amount} nets below {min_net} at {fee_bp} bp"
        );
        assert!(
            net(amount - U256::ONE, fee_bp) < min_net,
            "{amount} is not minimal for {min_net} at {fee_bp} bp"
        );
    }

    #[test]
    fn min_shield_amount_is_the_smallest_amount_meeting_the_net() {
        assert_eq!(
            min_shield_amount(U256::from(9_975), U256::from(25)),
            Ok(U256::from(9_999))
        );
        assert_minimal(U256::from(9_999), U256::from(9_975), 25);
        for fee_bp in [0, 1, 25, 50, 333, 5_000, 9_999] {
            for min_net in 1..=3_000_u64 {
                let min_net = U256::from(min_net);
                let amount = min_shield_amount(min_net, U256::from(fee_bp)).unwrap();
                assert_minimal(amount, min_net, fee_bp);
            }
        }
    }

    #[test]
    fn min_shield_amount_near_the_note_value_limit() {
        let max = (U256::ONE << 120) - U256::ONE;
        assert_eq!(min_shield_amount(max, U256::ZERO), Ok(max));
        assert_eq!(
            min_shield_amount(max, U256::from(25)),
            Err(ShieldFeeError::Overflow)
        );
        let min_net = net(max, 25);
        let amount = min_shield_amount(min_net, U256::from(25)).unwrap();
        assert!(amount <= max);
        assert_minimal(amount, min_net, 25);
    }

    #[test]
    fn min_shield_amount_rejects_unusable_inputs() {
        assert_eq!(
            min_shield_amount(U256::ZERO, U256::from(25)),
            Err(ShieldFeeError::ZeroMinimum)
        );
        assert_eq!(
            min_shield_amount(U256::ONE, U256::from(FEE_BASIS_POINTS)),
            Err(ShieldFeeError::FeeTooHigh)
        );
        assert_eq!(
            min_shield_amount(U256::MAX, U256::ZERO),
            Err(ShieldFeeError::Overflow)
        );
    }
}
