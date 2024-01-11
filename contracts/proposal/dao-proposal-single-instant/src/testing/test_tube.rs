#[cfg(test)]
pub mod test_tube {
    use crate::contract::compute_sha256_hash;
    use crate::msg::{ExecuteMsg, InstantiateMsg, SingleChoiceInstantProposalMsg};
    use crate::state::VoteSignature;
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{to_json_binary, Api, BankMsg, Coin, CosmosMsg, Uint128};
    use cw_utils::Duration;
    use dao_interface::msg::InstantiateMsg as InstantiateMsgCore;
    use dao_interface::state::Admin;
    use dao_interface::state::ModuleInstantiateInfo;
    use dao_voting::pre_propose::PreProposeInfo;
    use dao_voting::threshold::Threshold;
    use dao_voting_cw4::msg::GroupContract;
    use osmosis_test_tube::osmosis_std::types::cosmos::bank::v1beta1::{
        MsgSend, QueryBalanceRequest,
    };
    use osmosis_test_tube::osmosis_std::types::cosmos::base::v1beta1;
    use osmosis_test_tube::RunnerError::ExecuteError;
    use osmosis_test_tube::{Account, Bank};
    use osmosis_test_tube::{Module, OsmosisTestApp, SigningAccount, Wasm};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use sha2::Digest;

    /// Init constants
    const SLUG_DAO_DAO_CORE: &str = "dao_dao_core";
    const SLUG_CW4_GROUP: &str = "cw4_group";
    const SLUG_DAO_VOTING_CW4: &str = "dao_voting_cw4";
    const SLUG_DAO_PROPOSAL_SINGLE_INSTANT: &str = "dao_proposal_single_instant";

    /// Test constants
    const INITIAL_BALANCE_AMOUNT: u128 = 1_000_000_000_000_000u128;
    const INITIAL_BALANCE_DENOM: &str = "ugov";

    pub fn test_init(
        voters_number: u32,
    ) -> (
        OsmosisTestApp,
        HashMap<&'static str, String>,
        SigningAccount,
        Vec<SigningAccount>,
    ) {
        // Create new osmosis appchain instance
        let app = OsmosisTestApp::new();
        let wasm = Wasm::new(&app);

        // Create new admin account with initial funds
        // The contract admin, to be used during store code.
        let admin: SigningAccount = app
            .init_account(&[
                Coin::new(INITIAL_BALANCE_AMOUNT, "uosmo"),
                Coin::new(INITIAL_BALANCE_AMOUNT, INITIAL_BALANCE_DENOM),
            ])
            .unwrap();

        // Create voters accounts with initial funds
        let mut voters: Vec<SigningAccount> = vec![];
        for _ in 0..voters_number {
            voters.push(
                app.init_account(&[Coin::new(INITIAL_BALANCE_AMOUNT, "uosmo")])
                    .unwrap(),
            )
        }

        // Create a vector of cw4::Member
        let mut initial_members = voters
            .iter()
            .map(|voter| cw4::Member {
                addr: voter.address().to_string(),
                weight: 1,
            })
            .collect::<Vec<_>>();
        // Pushing proposer weight 0 account
        initial_members.push(cw4::Member {
            addr: admin.address().to_string(),
            weight: 0,
        });

        // Contracts to store and instantiate
        let contracts_setup: Vec<(&str, Vec<u8>)> = vec![
            (
                SLUG_CW4_GROUP,
                get_wasm_byte_code(SLUG_CW4_GROUP).expect(""), // this is copy pasted from outside as this workspace if not creating this artifact. it has been taken from https://github.com/CosmWasm/cw-plus/tree/v1.1.0
            ),
            (SLUG_DAO_VOTING_CW4, get_wasm_byte_code(SLUG_DAO_VOTING_CW4).expect("")),
            (
                SLUG_DAO_PROPOSAL_SINGLE_INSTANT,
                get_wasm_byte_code(SLUG_DAO_PROPOSAL_SINGLE_INSTANT).expect(""),
            ),
            (SLUG_DAO_DAO_CORE, get_wasm_byte_code(SLUG_DAO_DAO_CORE).expect("")),
        ];

        // Store contracts and declare a HashMap
        let code_ids: HashMap<&str, u64> = contracts_setup
            .iter()
            .map(|&(contract_name, ref wasm_byte_code)| {
                let code_id = wasm
                    .store_code(&wasm_byte_code, None, &admin)
                    .expect("Failed to store code")
                    .data
                    .code_id;

                (contract_name, code_id)
            })
            .collect();

        // Instantiate contract and sub-contracts
        // https://github.com/DA0-DA0/dao-contracts/wiki/Instantiating-a-DAO#proposal-module-instantiate-message
        let vote_module_instantiate_msg = dao_voting_cw4::msg::InstantiateMsg {
            group_contract: GroupContract::New {
                cw4_group_code_id: *code_ids.get(SLUG_CW4_GROUP).unwrap(),
                initial_members,
            },
        };
        let prop_module_instantiate_msg = InstantiateMsg {
            threshold: Threshold::AbsoluteCount {
                threshold: Uint128::new(2u128),
            },
            // TODO: Create an additional test variant as below
            // threshold: Threshold::ThresholdQuorum {
            //     threshold: PercentageThreshold,
            //     quorum: PercentageThreshold,
            // },
            max_voting_period: Duration::Height(1), // 1 block only to make it expire after the proposing block
            min_voting_period: None,
            only_members_execute: true,
            allow_revoting: false,
            pre_propose_info: PreProposeInfo::AnyoneMayPropose {},
            close_proposal_on_execution_failure: true,
            veto: None,
        };
        let dao_dao_core_instantiate_msg = InstantiateMsgCore {
            admin: Some(admin.address()),
            name: "DAO DAO Core".to_string(),
            description: "".to_string(),
            image_url: None,
            automatically_add_cw20s: true,
            automatically_add_cw721s: true,
            proposal_modules_instantiate_info: vec![ModuleInstantiateInfo {
                code_id: *code_ids.get(SLUG_DAO_PROPOSAL_SINGLE_INSTANT).unwrap(),
                msg: to_json_binary(&prop_module_instantiate_msg).unwrap(),
                admin: Some(Admin::CoreModule {}),
                funds: vec![],
                label: "DAO DAO governance module".to_string(),
            }],
            voting_module_instantiate_info: ModuleInstantiateInfo {
                code_id: *code_ids.get(SLUG_DAO_VOTING_CW4).unwrap(),
                msg: to_json_binary(&vote_module_instantiate_msg).unwrap(),
                admin: Some(Admin::CoreModule {}),
                funds: vec![],
                label: "DAO DAO voting module".to_string(),
            },
            initial_items: None,
            dao_uri: None,
        };
        let dao_dao_core_instantiate_resp = wasm
            .instantiate(
                *code_ids.get(SLUG_DAO_DAO_CORE).unwrap(),
                &dao_dao_core_instantiate_msg,
                Some(admin.address().as_str()),
                Some(SLUG_DAO_DAO_CORE),
                vec![].as_ref(),
                &admin,
            )
            .unwrap();

        // HashMap to store contract names and their addresses
        let mut contracts: HashMap<&str, String> = HashMap::new();

        for event in dao_dao_core_instantiate_resp.events {
            if event.ty == "wasm" {
                for attr in event.attributes {
                    match attr.key.as_str() {
                        "_contract_address" => {
                            contracts
                                .entry(SLUG_DAO_DAO_CORE)
                                .or_insert_with(|| attr.value.clone());
                        }
                        "voting_module" => {
                            contracts
                                .entry(SLUG_DAO_VOTING_CW4)
                                .or_insert_with(|| attr.value.clone());
                        }
                        "prop_module" => {
                            contracts
                                .entry(SLUG_DAO_PROPOSAL_SINGLE_INSTANT)
                                .or_insert_with(|| attr.value.clone());
                        }
                        _ => {}
                    }
                }
            }
        }
        // TODO: Assert that we have the required n. of contracts here, as the ^ nested for match could fail

        // Increase app time or members will not have any voting power assigned
        app.increase_time(10000);

        (app, contracts, admin, voters)
    }
/*
    fn get_wasm_byte_code(filename: &str) -> Vec<u8> {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let byte_code = std::fs::read(
            manifest_path
                .join("..")
                .join("..")
                .join("..")
                .join("artifacts")
                .join(format!("{}.wasm", filename)),
        );
        match byte_code {
            Ok(byte_code) => byte_code,
            // On arm processors, the above path is not found, so we try the following path
            Err(_) => std::fs::read(
                manifest_path
                    .join("..")
                    .join("..")
                    .join("..")
                    .join("artifacts")
                    .join(format!("{}-aarch64.wasm", filename)),
            )
            .unwrap(),
        }
    }
*/
    fn get_wasm_byte_code(filename: &str) -> Result<Vec<u8>, std::io::Error> {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let wasm_path = manifest_path
            .join("..")
            .join("..")
            .join("..")
            .join("artifacts")
            .join(format!("{}.wasm", filename));

        if let Ok(byte_code) = std::fs::read(&wasm_path) {
            Ok(byte_code)
        } else {
            let alt_path = wasm_path.with_file_name(format!("{}-aarch64.wasm", filename));
            std::fs::read(&alt_path)
        }
    }


    #[test]
    #[ignore]
    /// Test case of a proposal creation, voting passing and executing all-in-once, which should move gov funds from treasury.
    fn test_dao_proposal_single_instant_ok_send() {
        let (app, contracts, admin, voters) = test_init(5);
        let bank = Bank::new(&app);
        let wasm = Wasm::new(&app);

        // Create proposal execute msg as bank message from treasury back to the admin account
        let bank_send_amount = 1000u128;
        let execute_propose_msg = CosmosMsg::Bank(BankMsg::Send {
            to_address: admin.address(),
            amount: vec![Coin {
                denom: INITIAL_BALANCE_DENOM.to_string(),
                amount: Uint128::new(bank_send_amount),
            }],
        });
        let execute_propose_msg_binary = to_json_binary(&execute_propose_msg).unwrap();

        // Creating different messages for each voter.
        // ... add as many messages as there are voters
        // The number of items of this array should match the test_init({voters_number}) value.
        let messages: Vec<&[u8]> = vec![
            execute_propose_msg_binary.as_slice(), // A <- will pass!
            execute_propose_msg_binary.as_slice(), // A <- will pass!
            execute_propose_msg_binary.as_slice(), // A <- will pass!
            b"Hello World!",                       // B
            b"Hello World!",                       // B
        ];

        let mut vote_signatures: Vec<VoteSignature> = vec![];
        for (index, voter) in voters.iter().enumerate() {
            // Ensure that there's a message for each voter
            if let Some(clear_message) = messages.get(index) {
                let message_hash = compute_sha256_hash(clear_message);
                let signature = voter.signing_key().sign(clear_message).unwrap();
                // VoteSignature
                vote_signatures.push(VoteSignature {
                    message_hash,
                    signature: signature.as_ref().to_vec(),
                    public_key: voter.public_key().to_bytes(),
                });
            } else {
                // Do nothing in the case where there's no message for a voter
            }
        }

        // Get Admin balance before send
        let admin_balance_before = bank
            .query_balance(&QueryBalanceRequest {
                address: admin.address(),
                denom: INITIAL_BALANCE_DENOM.to_string(),
            })
            .unwrap()
            .balance
            .expect("failed to query balance");

        // Execute bank send from admin to treasury
        bank.send(
            MsgSend {
                from_address: admin.address(),
                to_address: contracts
                    .get(SLUG_DAO_DAO_CORE)
                    .expect("Treasury address not found")
                    .clone(),
                amount: vec![v1beta1::Coin {
                    denom: INITIAL_BALANCE_DENOM.to_string(),
                    amount: bank_send_amount.to_string(),
                }],
            },
            &admin,
        )
        .unwrap();

        // Get Admin balance after send
        let admin_balance_after_send = bank
            .query_balance(&QueryBalanceRequest {
                address: admin.address(),
                denom: INITIAL_BALANCE_DENOM.to_string(),
            })
            .unwrap()
            .balance
            .expect("failed to query balance");
        let admin_balance_after = admin_balance_after_send
            .amount
            .parse::<u128>()
            .expect("Failed to parse after balance");
        let admin_balance_before = admin_balance_before
            .amount
            .parse::<u128>()
            .expect("Failed to parse before balance");
        assert!(admin_balance_after == admin_balance_before - bank_send_amount);

        // Get treasury balance after send
        let treasury_balance_after_send = bank
            .query_balance(&QueryBalanceRequest {
                address: contracts
                    .get(SLUG_DAO_DAO_CORE)
                    .expect("Treasury address not found")
                    .clone(),
                denom: INITIAL_BALANCE_DENOM.to_string(),
            })
            .unwrap()
            .balance
            .expect("failed to query balance");
        let treasury_balance_after = treasury_balance_after_send
            .amount
            .parse::<u128>()
            .expect("Failed to parse after balance");
        assert!(treasury_balance_after == bank_send_amount);

        // Execute execute_propose (proposal, voting and execution in one single workflow)
        let _execute_propose_resp = wasm
            .execute(
                contracts.get(SLUG_DAO_PROPOSAL_SINGLE_INSTANT).unwrap(),
                &ExecuteMsg::Propose(SingleChoiceInstantProposalMsg {
                    title: "Title".to_string(),
                    description: "Description".to_string(),
                    msgs: vec![execute_propose_msg],
                    proposer: None,
                    vote_signatures,
                }),
                &vec![],
                &admin,
            )
            .unwrap();

        // Get Admin balance after proposal
        let admin_balance_after_proposal = bank
            .query_balance(&QueryBalanceRequest {
                address: admin.address(),
                denom: INITIAL_BALANCE_DENOM.to_string(),
            })
            .unwrap()
            .balance
            .expect("failed to query balance");
        let admin_balance_after = admin_balance_after_proposal
            .amount
            .parse::<u128>()
            .expect("Failed to parse after balance");

        assert!(admin_balance_after == admin_balance_before);
    }

    // TODO: fn test_dao_proposal_single_instant_ok_range_update()
    // - This should import the range-middleware contract and be working against it
    // let exec: CosmosMsg = CosmosMsg::Wasm(WasmMsg::Execute {
    //     contract_addr: "osmo1ac0mdjddlu8rxxqhznjegggj8826azfjr6p8kssfue4gm2x5twqqjypz3n"
    //         .to_string(),
    //     msg: to_json_binary(&RangeExecuteMsg::SubmitNewRange {
    //         new_range: NewRange {
    //             cl_vault_address:
    //                 "osmo18u9fdx9dahzsama4g0h7tf46hsz7gldvsw392q8al69jy4p2m79shmkam7"
    //                     .to_string(),
    //             lower_price: Decimal::from_str("1.0").unwrap(),
    //             upper_price: Decimal::from_str("1.5").unwrap(),
    //         },
    //     })
    //     .unwrap(),
    //     funds: vec![],
    // });

    #[test]
    #[ignore]
    /// Test case of a proposal failing due to a tie in message_hash_majority computation by voting_power.
    fn test_dao_proposal_single_instant_ko_tie() {
        let (app, contracts, admin, voters) = test_init(5);
        let wasm = Wasm::new(&app);

        // Creating different messages for each voter.
        // The number of items of this array should match the test_init({voters_number}) value.
        let messages: Vec<&[u8]> = vec![
            b"Hello World! 0",
            b"Hello World! 1",
            b"Hello World! 2",
            b"Hello World! 3",
            b"Hello World! 4",
            // ... add as many messages as there are voters
        ];

        let mut vote_signatures: Vec<VoteSignature> = vec![];
        for (index, voter) in voters.iter().enumerate() {
            // Ensure that there's a message for each voter
            if let Some(clear_message) = messages.get(index) {
                let message_hash = compute_sha256_hash(clear_message);
                let signature = voter.signing_key().sign(clear_message).unwrap();

                // VoteSignature
                vote_signatures.push(VoteSignature {
                    message_hash,
                    signature: signature.as_ref().to_vec(),
                    public_key: voter.public_key().to_bytes(),
                });
            } else {
                // Do nothing in the case where there's no message for a voter
            }
        }

        // Execute execute_propose (proposal, voting and execution in one single workflow)
        let execute_propose_resp = wasm
            .execute(
                contracts.get(SLUG_DAO_PROPOSAL_SINGLE_INSTANT).unwrap(),
                &ExecuteMsg::Propose(SingleChoiceInstantProposalMsg {
                    title: "Title".to_string(),
                    description: "Description".to_string(),
                    msgs: vec![],
                    proposer: None,
                    vote_signatures,
                }),
                &vec![],
                &admin,
            )
            .unwrap_err();

        // Assert that the response is an error of a specific type (Unauthorized)
        assert!(
            matches!(execute_propose_resp, ExecuteError { msg } if msg.contains("failed to execute message; message index: 0: Not possible to reach required (passing) threshold: execute wasm contract failed"))
        );
    }

    #[test]
    #[ignore]
    /// Test case of a proposal failing due to not be reaching the minimum members quorum.
    fn test_dao_proposal_single_instant_ko_not_quorum() {
        let (app, contracts, admin, voters) = test_init(2);
        let wasm = Wasm::new(&app);

        // Creating different messages for each voter.
        // The number of items of this array should match the test_init({voters_number}) value.
        let messages: Vec<&[u8]> = vec![
            b"Hello World!", // only one vote when 2 is required on test_init() fixture
        ];

        let mut vote_signatures: Vec<VoteSignature> = vec![];
        for (index, voter) in voters.iter().enumerate() {
            // Ensure that there's a message for each voter
            if let Some(clear_message) = messages.get(index) {
                let message_hash = compute_sha256_hash(clear_message);
                let signature = voter.signing_key().sign(clear_message).unwrap();

                // VoteSignature
                vote_signatures.push(VoteSignature {
                    message_hash,
                    signature: signature.as_ref().to_vec(),
                    public_key: voter.public_key().to_bytes(),
                });
            } else {
                // Do nothing in the case where there's no message for a voter
            }
        }

        // Execute execute_propose (proposal, voting and execution in one single workflow)
        let execute_propose_resp = wasm
            .execute(
                contracts.get(SLUG_DAO_PROPOSAL_SINGLE_INSTANT).unwrap(),
                &ExecuteMsg::Propose(SingleChoiceInstantProposalMsg {
                    title: "Title".to_string(),
                    description: "Description".to_string(),
                    msgs: vec![],
                    proposer: None,
                    vote_signatures,
                }),
                &vec![],
                &admin,
            )
            .unwrap_err();

        // Assert that the response is an error of a specific type
        assert!(
            matches!(execute_propose_resp, ExecuteError { msg } if msg.contains("failed to execute message; message index: 0: proposal is not in 'passed' state: execute wasm contract failed"))
        );
    }

    #[test]
    #[ignore]
    /// Test case of a proposal failing due to be proposed by the a member of the same validator set, without passing trough the 0 voting power proposer role.
    fn test_dao_proposal_single_instant_ko_proposer() {
        let (app, contracts, _admin, voters) = test_init(3);
        let wasm = Wasm::new(&app);

        // Creating different messages for each voter.
        // The number of items of this array should match the test_init({voters_number}) value.
        let messages: Vec<&[u8]> = vec![b"Hello World!", b"Hello World!", b"Hello World!"];

        let mut vote_signatures: Vec<VoteSignature> = vec![];
        for (index, voter) in voters.iter().enumerate() {
            // Ensure that there's a message for each voter
            if let Some(clear_message) = messages.get(index) {
                let message_hash = compute_sha256_hash(clear_message);
                let signature = voter.signing_key().sign(clear_message).unwrap();

                // VoteSignature
                vote_signatures.push(VoteSignature {
                    message_hash,
                    signature: signature.as_ref().to_vec(),
                    public_key: voter.public_key().to_bytes(),
                });
            } else {
                // Do nothing in the case where there's no message for a voter
            }
        }

        // Execute execute_propose (proposal, voting and execution in one single workflow)
        let execute_propose_resp = wasm
            .execute(
                contracts.get(SLUG_DAO_PROPOSAL_SINGLE_INSTANT).unwrap(),
                &ExecuteMsg::Propose(SingleChoiceInstantProposalMsg {
                    title: "Title".to_string(),
                    description: "Description".to_string(),
                    msgs: vec![],
                    proposer: None,
                    vote_signatures,
                }),
                &vec![],
                &voters.get(0).unwrap(), // using first voter instead of admin to vote as member with voting power > 0
            )
            .unwrap_err();

        // Assert that the response is an error of a specific type (Unauthorized)
        assert!(
            matches!(execute_propose_resp, ExecuteError { msg } if msg.contains("failed to execute message; message index: 0: unauthorized: execute wasm contract failed"))
        );
    }

    #[test]
    #[ignore]
    fn test_secp256k1_verify() {
        let (_app, _contracts, _admin, voters) = test_init(100);
        let deps = mock_dependencies();

        for voter in voters {
            let public_key = voter.public_key();
            let clear_message = b"Hello World";
            let message_hash = compute_sha256_hash(clear_message);
            let signature = voter.signing_key().sign(clear_message).unwrap();

            let verified = deps
                .api
                .secp256k1_verify(
                    message_hash.as_slice(),
                    signature.as_ref(),
                    public_key.to_bytes().as_ref(),
                )
                .expect("Invalid signature");

            assert!(verified == true);
        }
    }

    #[test]
    #[ignore]

    // Using hex string
    fn test_secp256k1_verify2() {
        let (_app, _contracts, _admin, voters) = test_init(100);
        let deps = mock_dependencies();


        let public_key = hex::decode("03a15c6f3b22c41c6a36afe814ddfc6b8e912af0e94fea904427b0620c44877bf4");
        let message_hash = hex::decode("47e9eec6aa4d5fd5c6bcdd51a5c61e11c726c60c4c497daa9b96283b775d373c");
        let signature =  hex::decode("9e8fc8eaabaecd1e24da62349bf8e91565efb5e61524b406a9beefde2572ccfacf65c8128f9ded4528e04c78346b508b25a1be9d1b8d8ed8e510738868985abb");

        let verified = deps
            .api
            .secp256k1_verify(
                message_hash.unwrap().as_slice(),
                signature.unwrap().as_slice(),
                public_key.unwrap().as_slice(),
            )
            .expect("Invalid signature");

        assert!(verified == true);
    }



    #[test]
    #[ignore]
    // Using binary array
    fn test_secp256k1_verify3() {
        let (_app, _contracts, _admin, voters) = test_init(100);
        let deps = mock_dependencies();


        let message_hash: Vec<u8> = vec![
            0x47, 0xe9, 0xee, 0xc6, 0xaa, 0x4d, 0x5f, 0xd5, 0xc6, 0xbc, 0xdd, 0x51, 0xa5, 0xc6, 0x1e, 0x11,
            0xc7, 0x26, 0xc6, 0x0c, 0x4c, 0x49, 0x7d, 0xaa, 0x9b, 0x96, 0x28, 0x3b, 0x77, 0x5d, 0x37, 0x3c
        ];
        let signature: Vec<u8> = vec![
            0xa9, 0x47, 0x44, 0xef, 0x1d, 0x9e, 0xd0, 0x72, 0x79, 0x26, 0xee, 0x44, 0x6f, 0xde, 0x3f, 0x40,
            0x26, 0x8f, 0xee, 0x4b, 0xc4, 0xb9, 0xf3, 0x88, 0xd2, 0xfc, 0x98, 0xcb, 0x84, 0x35, 0xa7, 0xc7,
            0xdb, 0xd5, 0x17, 0x94, 0x40, 0xd0, 0x65, 0x05, 0x53, 0x49, 0x4e, 0xae, 0xf9, 0x5b, 0x36, 0x92,
            0x1c, 0x3d, 0x89, 0x95, 0x7b, 0x26, 0xd8, 0x3b, 0x1b, 0xa4, 0xc1, 0x9b, 0xec, 0xc0, 0x8f, 0x7d,
        ];
        let public_key: Vec<u8> = vec![
            0x03, 0xa1, 0x5c, 0x6f, 0x3b, 0x22, 0xc4, 0x1c, 0x6a, 0x36, 0xaf, 0xe8, 0x14, 0xdd, 0xfc, 0x6b, 0x8e,
            0x91, 0x2a, 0xf0, 0xe9, 0x4f, 0xea, 0x90, 0x44, 0x27, 0xb0, 0x62, 0x0c, 0x44, 0x87, 0x7b, 0xf4,
        ];


        let verified = deps
            .api
            .secp256k1_verify(
                message_hash.as_slice(),
                signature.as_slice(),
                public_key.as_slice(),
            )
            .expect("Invalid signature");

        assert!(verified == true);


    }




    #[test]
    #[ignore]
    // The purpose of this test method is to check the message initialization in two different rust ways.
    // Useful to generate different formats of hash messages as hex, and byte arrays
    fn test_wasm_message_serializations() {
        let (_app, _contracts, _admin, voters) = test_init(100);
        let deps = mock_dependencies();

        let execute_msg = cosmwasm_std::WasmMsg::Execute {
            contract_addr: "osmo1ac0mdjddlu8rxxqhznjegggj8826azfjr6p8kssfue4gm2x5twqqjypz3n".to_string(),
            funds: vec![],
            msg: cosmwasm_std::Binary::from_base64("eyJyYW5nZV9tc2ciOnsic3VibWl0X25ld19yYW5nZSI6eyJuZXdfcmFuZ2UiOnsiY2xfdmF1bHRfYWRkcmVzcyI6Im9zbW8xOHU5ZmR4OWRhaHpzYW1hNGcwaDd0ZjQ2aHN6N2dsZHZzdzM5MnE4YWw2OWp5NHAybTc5c2hta2FtNyIsImxvd2VyX3ByaWNlIjoiMS4wIiwidXBwZXJfcHJpY2UiOiIxLjUifX19fQ==").unwrap(),
        };

        let cosmos_msg: CosmosMsg<cosmwasm_std::Empty> = CosmosMsg::Wasm(execute_msg);
        let serialized_msg = cosmwasm_std::to_binary(&cosmos_msg).unwrap();
        println!("serialized_msg: {:?}", serialized_msg);
        println!("serialized_msg_slice: {:?}", serialized_msg.as_slice());

        let mut hasher = sha2::Sha256::new();
        hasher.update(serialized_msg.as_slice());
        let result = hasher.finalize();
        println!("message_hash - {:?}", result.to_vec());

        let hash_bytes: Vec<u8> = result.into_iter().collect();

        // Format the hash bytes as [0xcc, 0x94, 0x3d, ...]
        let hash_formatted: String = hash_bytes
            .iter()
            .map(|byte| format!("0x{:02x}", byte))
            .collect::<Vec<String>>()
            .join(", ");
        println!("hash bytes : [{}]", hash_formatted);

        //let hash_bytes: Vec<u8> = result.into_iter().collect();
        let hash_hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        println!("hash_hex: {:?}", hash_hex);

        println!("=================================");

        let execute_msg_2 = cosmwasm_std::WasmMsg::Execute {
            contract_addr: "osmo1ac0mdjddlu8rxxqhznjegggj8826azfjr6p8kssfue4gm2x5twqqjypz3n".to_string(),
            msg: cosmwasm_std::Binary::from(br#"{"range_msg":{"submit_new_range":{"new_range":{"cl_vault_address":"osmo18u9fdx9dahzsama4g0h7tf46hsz7gldvsw392q8al69jy4p2m79shmkam7","lower_price":"1.0","upper_price":"1.5"}}}}"#.to_vec()),
            funds: vec![],
        };

        //let cosmos_msg = cosmwasm_std::CosmosMsg::Wasm(execute_propose_msg_2);
        let cosmos_msg: CosmosMsg<cosmwasm_std::Empty> = CosmosMsg::Wasm(execute_msg_2);
        let serialized_msg = cosmwasm_std::to_binary(&cosmos_msg).unwrap();
        println!("serialized_msg - {:?}", serialized_msg);
        let message_hash = compute_sha256_hash(serialized_msg.as_slice());
        println!("message_hash - {:?}", message_hash);
        let hash_bytes: Vec<u8> = message_hash.into_iter().collect();
        // Format the hash bytes as [0xcc, 0x94, 0x3d, ...]
        let hash_formatted: String = hash_bytes
            .iter()
            .map(|byte| format!("0x{:02x}", byte))
            .collect::<Vec<String>>()
            .join(", ");
        println!("hash bytes : [{}]", hash_formatted);
        let hash_hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        println!("hash_hex: {:?}", hash_hex);

    }


    #[test]
    #[ignore]
    // Test case for checking serialisation and message hash and for sending middleware message.
    // The purpose is to only check if the message send works.
    // TODO - Using actual middleware contract and checking against that, here in this case
    // It should have failed because giving a unknown contract address.
    fn test_prop_single_instant_msg_serialization_checks_1() {

        let (app, contracts, admin, voters) = test_init(3);
        let bank = Bank::new(&app);
        let wasm = Wasm::new(&app);


        // Sending middleware submit wasm message
        let execute_propose_msg_2 = cosmwasm_std::WasmMsg::Execute {
            contract_addr: "osmo1ac0mdjddlu8rxxqhznjegggj8826azfjr6p8kssfue4gm2x5twqqjypz3n".to_string(),
            msg: cosmwasm_std::Binary::from(br#"{"range_msg":{"submit_new_range":{"new_range":{"cl_vault_address":"osmo18u9fdx9dahzsama4g0h7tf46hsz7gldvsw392q8al69jy4p2m79shmkam7","lower_price":"1.0","upper_price":"1.5"}}}}"#.to_vec()),
            funds: vec![],
        };
        let execute_propose_msg_2_clone = execute_propose_msg_2.clone();

        let cosmos_msg: CosmosMsg<cosmwasm_std::Empty> = CosmosMsg::Wasm(execute_propose_msg_2);
        let serialized_msg = cosmwasm_std::to_binary(&cosmos_msg).unwrap();

        println!("serialized_msg - {:?}", serialized_msg);

        let messages: Vec<&[u8]> = vec![
            serialized_msg.as_slice(), // A <- will pass!
            serialized_msg.as_slice(), // A <- will pass!
            serialized_msg.as_slice(), // A <- will pass!
        ];
        let mut vote_signatures: Vec<VoteSignature> = vec![];
        for (index, voter) in voters.iter().enumerate() {
            // Ensure that there's a message for each voter
            if let Some(clear_message) = messages.get(index) {
                let message_hash = compute_sha256_hash(clear_message);
                println!("message_hash - {:?}", message_hash);
                let signature = voter.signing_key().sign(clear_message).unwrap();
                // VoteSignature
                vote_signatures.push(VoteSignature {
                    message_hash,
                    signature: signature.as_ref().to_vec(),
                    public_key: voter.public_key().to_bytes(),
                });
            } else {
                // Do nothing in the case where there's no message for a voter
            }
        }

        println!("vote_signatures - {:?}", vote_signatures);


        // Execute execute_propose (proposal, voting and execution in one single workflow)
        let _execute_propose_resp = wasm
            .execute(
                contracts.get(SLUG_DAO_PROPOSAL_SINGLE_INSTANT).unwrap(),
                &ExecuteMsg::Propose(SingleChoiceInstantProposalMsg {
                    title: "Title".to_string(),
                    description: "Description".to_string(),
                    msgs: vec![cosmwasm_std::CosmosMsg::Wasm(execute_propose_msg_2_clone)],
                    proposer: None,
                    vote_signatures,
                }),
                &vec![],
                &admin,
            );
        // .unwrap();
        match _execute_propose_resp {
            Ok(_) =>  {
                println!("OK - {:?}", _execute_propose_resp);
            }
            Err(e) => {
                // Check if the error is the expected one
                let error_message = format!("{:?}", e);
                println!("error message - {:?}", error_message);
                // assert!(error_message.contains("Not possible to reach required (passing) threshold"), "Unexpected error message: {}", error_message);
            }
        }

    }


}
