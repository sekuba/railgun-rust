//! Native shield execution by a delegated account, checked against SDK-generated vectors.

use alloy::eips::eip7702::Authorization;
use alloy::primitives::{Address, Bytes, U256, address};
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;
use broadcaster_core::contracts::executor::{execute_signing_hash, native_shield_action_data};
use broadcaster_core::contracts::railgun::{RelayAdapt7702, shieldCall, wrapBaseCall};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/sdk-shield.json")).expect("SDK shield fixture")
}

fn parse<T: std::str::FromStr>(value: &Value) -> T
where
    T::Err: std::fmt::Debug,
{
    value.as_str().expect("string").parse().expect("parsable")
}

#[test]
fn native_shield_matches_sdk() {
    let fixture = fixture();
    let executor: Address = parse(&fixture["executorAddress"]);
    let signer: PrivateKeySigner = parse(&fixture["inputs"]["executorKey"]);
    assert_eq!(signer.address(), executor);
    let amount: U256 = parse(&fixture["inputs"]["amount"]);

    let vectors = fixture["native"].as_array().unwrap();
    assert_eq!(vectors.len(), 4);
    for vector in vectors {
        let chain_id = vector["chainId"].as_u64().unwrap();
        let delegate: Address = parse(&vector["delegate"]);
        let expected_delegate = if chain_id == 1 {
            address!("0x1F74b4339990Db761bC0168F20D294A3a141497e")
        } else {
            assert!([56, 137, 42161].contains(&chain_id));
            address!("0xa2BFd382c54bb33DF6A13f21acd8770dc1e67D4D")
        };
        assert_eq!(delegate, expected_delegate);

        let request = shieldCall::abi_decode(&parse::<Bytes>(&vector["shieldCalldata"]))
            .expect("shield calldata")
            ._shieldRequests
            .remove(0);
        assert_eq!(U256::from(request.preimage.value), amount);
        let shield_data = shieldCall {
            _shieldRequests: vec![request.clone()],
        }
        .abi_encode();

        let transaction = &vector["transaction"];
        assert_eq!(transaction["type"], 4);
        assert_eq!(parse::<Address>(&transaction["to"]), executor);
        assert_eq!(parse::<U256>(&transaction["value"]), amount);
        let data: Bytes = parse(&transaction["data"]);
        let call = RelayAdapt7702::executeCall::abi_decode(&data).expect("execute calldata");
        assert!(call._transactions.is_empty());
        assert_eq!(call._nonce, U256::ZERO);

        let action = native_shield_action_data(executor, request).expect("native action data");
        assert!(action.requireSuccess);
        assert_eq!(action.minGasLimit, U256::ZERO);
        let expected_calls = [wrapBaseCall { _amount: amount }.abi_encode(), shield_data];
        assert_eq!(action.calls.len(), expected_calls.len());
        assert_eq!(call._actionData.calls.len(), expected_calls.len());
        for ((built, decoded), expected_data) in action
            .calls
            .iter()
            .zip(&call._actionData.calls)
            .zip(&expected_calls)
        {
            assert_eq!(built.to, executor);
            assert_eq!(built.value, U256::ZERO);
            assert_eq!(built.data.as_ref(), expected_data.as_slice());
            assert_eq!(
                (built.to, &built.data, built.value),
                (decoded.to, &decoded.data, decoded.value)
            );
        }
        assert_eq!(action.requireSuccess, call._actionData.requireSuccess);
        assert_eq!(action.minGasLimit, call._actionData.minGasLimit);

        let signature = signer
            .sign_hash_sync(&execute_signing_hash(
                &[],
                &action,
                U256::ZERO,
                chain_id,
                executor,
            ))
            .unwrap();
        assert_eq!(call._signature.as_ref(), signature.as_bytes().as_slice());
        let encoded = RelayAdapt7702::executeCall {
            _transactions: vec![],
            _actionData: action,
            _nonce: U256::ZERO,
            _signature: Bytes::copy_from_slice(&signature.as_bytes()),
        }
        .abi_encode();
        assert_eq!(encoded, data.as_ref());

        let expected = &transaction["authorization"];
        let authorization = Authorization {
            chain_id: U256::from(chain_id),
            address: delegate,
            nonce: 0,
        };
        assert_eq!(
            parse::<Address>(&expected["address"]),
            authorization.address
        );
        assert_eq!(parse::<U256>(&expected["chainId"]), authorization.chain_id);
        assert_eq!(parse::<u64>(&expected["nonce"]), authorization.nonce);
        let signature = signer
            .sign_hash_sync(&authorization.signature_hash())
            .unwrap();
        let expected = &expected["signature"];
        assert_eq!(
            expected["yParity"].as_u64().unwrap(),
            u64::from(signature.v())
        );
        assert_eq!(parse::<U256>(&expected["r"]), signature.r());
        assert_eq!(parse::<U256>(&expected["s"]), signature.s());
    }
}
