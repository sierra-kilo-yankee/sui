// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    base_types::SuiAddress,
    crypto::{get_key_pair_from_rng, DefaultHash, Signature, SuiKeyPair},
    openid_authenticator::{MaskedContent, OAuthProviderContent, OpenIdAuthenticator},
    signature::{AuthenticatorTrait, GenericSignature},
    utils::make_transaction,
};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::hash::HashFunction;
use rand::{rngs::StdRng, SeedableRng};
use shared_crypto::intent::{Intent, IntentMessage, IntentScope};

pub fn keys() -> Vec<SuiKeyPair> {
    let mut seed = StdRng::from_seed([0; 32]);
    let kp1: SuiKeyPair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut seed).1);
    let kp2: SuiKeyPair = SuiKeyPair::Secp256k1(get_key_pair_from_rng(&mut seed).1);
    let kp3: SuiKeyPair = SuiKeyPair::Secp256r1(get_key_pair_from_rng(&mut seed).1);
    vec![kp1, kp2, kp3]
}

#[test]
fn openid_authenticator_scenarios() {
    let keys = keys();
    let foundation_key = &keys[0];
    let user_key = &keys[1];

    // Make the user address out of the verifying key.
    let vk_gamma_abc_g1 = Hex::decode("58766b67a7ee2a07cb5400f400a18e5021c47f3948dba937b26b9bd9f2763487dbcbb0a9a9fa334b0e336ee629a4e9daaaa6fd071897c2ae8d3fb06f1aae2794").unwrap();
    let alpha_g1_beta_g2 = Hex::decode("2f76013a21c743416be59c187ba8af79f92d14df9d5bdad4f9d814e2f3b06116c9819556eeced83153f70d9043937360d6d8d1bb2e87514b7b29ec239fb3011f5e0b1528527780bb4e7f9ce4768befdcb9eb7cca9e58177878e0c5cbf2df0516adc9c5ede317e599bff0b3e025f7f15dd280269657d856d1632f4d93f29e352e3f1243e5fb60f5e9f420ffdcd4b43dab431eafcf428066804226354dc76bf91f557fe55da565400b26552a96a0fba98f780f522117944dab646e150cef3a6126cf191d47a94468a1b4545ce98e800a28a2d521f63eb31dcd736bbaf9bcca0502ffab151eec6f1a637fca2f293be339c020829f387acaf1b5088f27e138ea400d13a7253b11005476613e2177e1fa0f30e003639da707c527e876fb71abfb182758d016d92f70f6fcb3391dbe8b98cc90731a467a5e34cfe16718370db2641b236407beae969ba9e9158db78cba51865c73fd80be1933d5fd953ce4c2c5b83b2a61c727744c9a883b2b9611c4565b9e401ab05c83a8e8c904306cb39aa400a205").unwrap();
    let gamma_g2_neg_pc = Hex::decode("ec4e2164394291a6f16f06cb56b8e7e73e64bce87eb1461203f97e23a83ee519847d5fcd5bb16ce54381f69ba080e4e6667da14ff690c6ffd714c0f6a7de2d83").unwrap();
    let delta_g2_neg_pc = Hex::decode("744ae7b44221887f0abb47d82c5bea9cf1deb1d5a078f0e1a987f60b628aa5036a00de01f599236f18c9625c52017ec56544fe57cbaf6c4e8897cdc786458194").unwrap();

    let mut hasher = DefaultHash::default();
    hasher.update(&vk_gamma_abc_g1);
    hasher.update(&alpha_g1_beta_g2);
    hasher.update(&gamma_g2_neg_pc);
    hasher.update(&delta_g2_neg_pc);
    let user_address = SuiAddress::from_bytes(hasher.finalize().digest).unwrap();

    // Create an example bulletin with 2 keys from Google.
    let example_bulletin = vec![
        OAuthProviderContent {
            iss: "https://accounts.google.com".to_string(),
            kty: "RSA".to_string(),
            kid: "986ee9a3b7520b494df54fe32e3e5c4ca685c89d".to_string(),
            e: "AQAB".to_string(),
            n: "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ".to_string(),
            alg: "RS256".to_string(),
        }
    ];

    // Sign the bulletin content with the sui foundation key as a personal message.
    let bulletin_sig = Signature::new_secure(
        &IntentMessage::new(
            Intent::sui_app(IntentScope::PersonalMessage),
            example_bulletin.clone(),
        ),
        foundation_key,
    );

    // Sign the user transaction with the user's ephemeral key.
    let tx = make_transaction(user_address, user_key, Intent::sui_transaction());
    let s = match tx.inner().tx_signatures.first().unwrap() {
        GenericSignature::Signature(s) => s,
        _ => panic!("Expected a signature"),
    };

    let authenticator = OpenIdAuthenticator {
        vk_gamma_abc_g1,
        alpha_g1_beta_g2,
        gamma_g2_neg_pc,
        delta_g2_neg_pc,
        proof_points: Hex::decode("1db043b70445f368f6ffa4c9f1fdc3982e53a791edd534f83d5d3a248682121cd52527cb53ee490d9bdb8c93e03142a53c070680d8558c8e11fa528a865d1d2afbbe8314a2a279245027323c97df050ed8eff3ac7cfff908bcb7e53669641226adc0d5cffab396cdabfeb32c971c78c0e615480b36c9709ef2997647e533c92a").unwrap(),
        hash: Hex::decode("c88a34847b4ffb12a9326e540f144b3dcc4d5515f18701e7d6e0ee7866c9c705").unwrap(),
        masked_content: MaskedContent {content: vec![]},
        max_epoch: 1,
        jwt_signature: base64_url::decode("cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw").unwrap(),
        user_signature: s.clone(),
        bulletin_signature: bulletin_sig,
        bulletin: example_bulletin
    };
    assert!(authenticator
        .verify_secure_generic(
            &IntentMessage::new(
                Intent::sui_transaction(),
                tx.into_data().transaction_data().clone()
            ),
            user_address,
            Some(0)
        )
        .is_ok());
}

#[test]
fn test_authenticator_failure() {}

#[test]
fn test_serde_roundtrip() {}

#[test]
fn test_open_id_authenticator_address() {}
