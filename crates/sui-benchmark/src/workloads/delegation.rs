// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::system_state_observer::SystemStateObserver;
use crate::workloads::payload::Payload;
use crate::workloads::workload::{Workload, WorkloadBuilder, MAX_GAS_FOR_TESTING};
use crate::workloads::{Gas, GasCoinConfig, WorkloadBuilderInfo, WorkloadParams};
use crate::{ExecutionEffects, ValidatorProxy};
use async_trait::async_trait;
use rand::seq::IteratorRandom;
use std::sync::Arc;
use sui_core::test_utils::make_transfer_sui_transaction;
use sui_types::base_types::{ObjectRef, SuiAddress};
use sui_types::crypto::{get_key_pair, AccountKeyPair};
use sui_types::messages::VerifiedTransaction;
use test_utils::messages::make_staking_transaction;

#[derive(Debug)]
pub struct DelegationTestPayload {
    coin: Option<ObjectRef>,
    gas: ObjectRef,
    validator: SuiAddress,
    sender: SuiAddress,
    keypair: Arc<AccountKeyPair>,
    system_state_observer: Arc<SystemStateObserver>,
}

impl std::fmt::Display for DelegationTestPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "delegation")
    }
}

impl Payload for DelegationTestPayload {
    fn make_new_payload(&mut self, effects: &ExecutionEffects) {
        let coin = match self.coin {
            None => Some(effects.created().get(0).unwrap().0),
            Some(_) => None,
        };
        self.coin = coin;
        self.gas = effects.gas_object().0;
    }

    /// delegation flow is split into two phases
    /// first `make_transaction` call creates separate coin object for future delegation
    /// followup call creates delegation transaction itself
    fn make_transaction(&mut self) -> VerifiedTransaction {
        match self.coin {
            Some(coin) => make_staking_transaction(
                self.gas,
                coin,
                self.validator,
                self.sender,
                &self.keypair,
                Some(
                    self.system_state_observer
                        .state
                        .borrow()
                        .reference_gas_price,
                ),
            ),
            None => make_transfer_sui_transaction(
                self.gas,
                self.sender,
                Some(1),
                self.sender,
                &self.keypair,
                Some(
                    self.system_state_observer
                        .state
                        .borrow()
                        .reference_gas_price,
                ),
            ),
        }
    }
}

#[derive(Debug)]
pub struct DelegationWorkloadBuilder {
    gas_price: u64,
    count: u64,
}

impl DelegationWorkloadBuilder {
    pub fn from(
        workload_weight: f32,
        target_qps: u64,
        num_workers: u64,
        in_flight_ratio: u64,
        gas_price: u64,
    ) -> Option<WorkloadBuilderInfo> {
        let target_qps = (workload_weight * target_qps as f32) as u64;
        let num_workers = (workload_weight * num_workers as f32).ceil() as u64;
        let max_ops = target_qps * in_flight_ratio;
        if max_ops == 0 || num_workers == 0 {
            None
        } else {
            let workload_params = WorkloadParams {
                target_qps,
                num_workers,
                max_ops,
            };
            let workload_builder = Box::<dyn WorkloadBuilder<dyn Payload>>::from(Box::new(
                DelegationWorkloadBuilder {
                    count: max_ops,
                    gas_price,
                },
            ));
            let builder_info = WorkloadBuilderInfo {
                workload_params,
                workload_builder,
            };
            Some(builder_info)
        }
    }
}

#[async_trait]
impl WorkloadBuilder<dyn Payload> for DelegationWorkloadBuilder {
    async fn generate_coin_config_for_init(&self) -> Vec<GasCoinConfig> {
        vec![]
    }
    async fn generate_coin_config_for_payloads(&self) -> Vec<GasCoinConfig> {
        (0..self.count)
            .map(|_| {
                let (address, keypair) = get_key_pair();
                GasCoinConfig {
                    amount: MAX_GAS_FOR_TESTING * self.gas_price,
                    address,
                    keypair: Arc::new(keypair),
                }
            })
            .collect()
    }
    async fn build(
        &self,
        _init_gas: Vec<Gas>,
        payload_gas: Vec<Gas>,
    ) -> Box<dyn Workload<dyn Payload>> {
        Box::<dyn Workload<dyn Payload>>::from(Box::new(DelegationWorkload { payload_gas }))
    }
}

#[derive(Debug)]
pub struct DelegationWorkload {
    payload_gas: Vec<Gas>,
}

#[async_trait]
impl Workload<dyn Payload> for DelegationWorkload {
    async fn init(
        &mut self,
        _: Arc<dyn ValidatorProxy + Sync + Send>,
        _system_state_observer: Arc<SystemStateObserver>,
    ) {
    }

    async fn make_test_payloads(
        &self,
        proxy: Arc<dyn ValidatorProxy + Sync + Send>,
        system_state_observer: Arc<SystemStateObserver>,
    ) -> Vec<Box<dyn Payload>> {
        let validators = proxy
            .get_validators()
            .await
            .expect("failed to fetch validators");

        self.payload_gas
            .iter()
            .map(|(gas, owner, keypair)| {
                let validator = *validators.iter().choose(&mut rand::thread_rng()).unwrap();
                Box::new(DelegationTestPayload {
                    coin: None,
                    gas: *gas,
                    validator,
                    sender: *owner,
                    keypair: keypair.clone(),
                    system_state_observer: system_state_observer.clone(),
                })
            })
            .map(|b| Box::<dyn Payload>::from(b))
            .collect()
    }
}
