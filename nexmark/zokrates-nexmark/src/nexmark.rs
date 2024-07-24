//! This module contains the code to execute the Nexmark queries, including passing the
//! outputs of one ZoKrates program as inputs to another.

use crate::abi::*;
use crate::input;
use crate::params::{program_name, Bls, Params, SigVariant};
use crate::verification;
use crate::zokrates::{aggregate_bls_signatures, compile, compute_witness, generate_proof, setup};
use crate::Options;
use hash_sign::sign::BLSAggregateSignature;
use itertools::multiunzip;
use itertools::Itertools;
use nexmark_datajson::{Auction, DataJson, SignedMessageJson};
use serde_json;
use std::collections::{BTreeMap, HashMap};

#[allow(non_snake_case)]
pub fn query1(params: Params, options: Options, data: DataJson) {
    let program_name = program_name("q1", &params);
    let n_messages = data.bids.len();
    compile_and_setup(&program_name, params, options, n_messages);

    let publicKey = input::get_public_key_eddsa(&data);
    let (msgs, bids, salts) = input::get_bids(&data.bids, n_messages);
    let signatures = input::get_eddsa_poseidon_signatures(&data.bids, n_messages);

    let inputs = match params.sig_variant {
        SigVariant::NoSig => Abi::Q1PoseidonNoSig(Q1PoseidonNoSigAbi { msgs, bids, salts }),
        SigVariant::Sig => Abi::Q1Poseidon(Q1PoseidonAbi {
            publicKey,
            msgs,
            bids,
            signatures,
        }),
    };

    let outputs = execute(&program_name, &program_name, inputs);

    let outputs_public = outputs[0..n_messages]
        .iter()
        .map(parse_u64)
        .collect::<Vec<_>>();
    println!("Results: {:?}", outputs_public);

    let aggsig = aggregate_signatures(&data.bids, params);
    verification::q1(&data, aggsig, params, options);
}

#[allow(non_snake_case)]
pub fn query4(params: Params, options: Options, data: DataJson) {
    let program_name_a = program_name("q4a", &params);
    let program_name_b = program_name("q4b", &params);
    let execution_name_a = |i: usize| format!("{program_name_a}-{i}");
    let execution_name_b = |i: usize| format!("{program_name_b}-{i}");
    let n_messages_a = 50; // Maximum number of bids per auction
    let n_messages_b = 10; // Maximum number of auctions per category
    compile_and_setup(&program_name_a, params, options, n_messages_a);
    compile_and_setup(&program_name_b, params, options, n_messages_b);

    // SUBQUERY A
    // Group the bids per auction
    let bids_per_auction = group_bids_per_auction(&data, n_messages_a);

    // Collect input parameters per group, and sort each group by price.
    let mut inputs_per_auction: Vec<(
        u64,
        (
            Vec<MessageMetadata>,
            Bids,
            Vec<Signature>,
            Vec<SaltPoseidon>,
        ),
    )> = Vec::new();
    let mut messages_in_order = Vec::new();
    for (&auction, group) in bids_per_auction.iter() {
        let sorted = sort_bids_by_price(&group);
        // println!("auction: {}, bids: {:?}", auction, sorted.len());
        messages_in_order.extend(sorted.clone());
        let (msgs, bids, salts) = input::get_bids(&sorted, n_messages_a);
        let signatures = input::get_eddsa_poseidon_signatures(&sorted, n_messages_a);
        inputs_per_auction.push((auction, (msgs, bids, signatures, salts)));
    }

    // Execute subquery for each group.
    let mut outputs_a: HashMap<u64, (u64, HashPoseidon, SaltPoseidon)> = HashMap::new();
    for (i, (auction, (msgs, bids, signatures, salts))) in
        inputs_per_auction.into_iter().enumerate()
    {
        println!("> Executing for auction {} with {} bids", auction, bids.n);
        let publicKey = input::get_public_key_eddsa(&data);
        let outputSalt = input::generate_salt_poseidon();
        let inputs_a = match params.sig_variant {
            SigVariant::NoSig => Abi::Q4aPoseidonNoSig(Q4aPoseidonNoSigAbi {
                msgs,
                bids,
                salts,
                outputSalt: outputSalt.clone(),
            }),
            SigVariant::Sig => Abi::Q4aPoseidon(Q4aPoseidonAbi {
                publicKey,
                msgs,
                bids,
                signatures,
                outputSalt: outputSalt.clone(),
            }),
        };
        let outputs = execute(&program_name_a, &execution_name_a(i), inputs_a);

        let price_private = parse_u64(&outputs[0]);
        let auction_public = parse_u64(&outputs[1]);
        let hashed_price_public = parse_hash_poseidon(&outputs[2]);
        println!(
            "For auction {}, max price is {}",
            auction_public, price_private
        );
        // println!("Hashed price: {}", hashed_price_public);
        outputs_a.insert(
            auction_public,
            (price_private, hashed_price_public, outputSalt),
        );
    }
    let n_a = outputs_a.len();

    // SUBQUERY B
    // Group the auctions per category
    // Note: the verifier must check whether this happened correctly, using the public data.
    let auction_ids = outputs_a.keys().cloned().collect::<Vec<_>>();
    let auctions_per_category = group_auctions_per_category(&auction_ids, &data, n_messages_b);

    // Collect input parameters per group.
    let mut inputs_per_category: Vec<(u64, (Vec<HashPoseidon>, U64s, Vec<SaltPoseidon>))> =
        Vec::new();
    for (&category, auction_ids) in auctions_per_category.iter() {
        println!("category: {}, auction_ids: {:?}", category, auction_ids);
        let (prices, hashes, salts): (Vec<u64>, Vec<HashPoseidon>, Vec<SaltPoseidon>) = auction_ids
            .iter()
            .map(|&auction_id| outputs_a.get(&auction_id).unwrap().clone())
            .multiunzip();
        let u64s = input::get_u64s(&prices, n_messages_b);
        inputs_per_category.push((category, (hashes, u64s, salts)));
    }

    // Execute subquery for each group.
    let mut outputs_b: HashMap<u64, u64> = HashMap::new();
    for (i, (category, (hashes, u64s, salts))) in inputs_per_category.into_iter().enumerate() {
        println!(
            "> Executing for category {} with {} values",
            category, u64s.n
        );
        let (valsHashes, salts) = input::get_hashes_salts(&hashes, &salts, n_messages_b);
        let inputs_b = match params.sig_variant {
            SigVariant::NoSig => Abi::Q4bPoseidonNoSig(Q4bPoseidonNoSigAbi {
                valsHashes,
                vals: u64s,
                salts,
            }),
            SigVariant::Sig => Abi::Q4bPoseidon(Q4bPoseidonAbi {
                valsHashes,
                vals: u64s,
                salts,
            }),
        };
        let outputs = execute(&program_name_b, &execution_name_b(i), inputs_b);

        let result = parse_u64(&outputs[0]);
        println!("For category {}, output is {}", category, result);
        outputs_b.insert(category, result);
    }
    let n_b = outputs_b.len();

    let aggsig = aggregate_signatures(&messages_in_order, params);
    verification::q4(&data, n_a, n_b, aggsig, params, options);
}

#[allow(non_snake_case)]
pub fn query5(params: Params, options: Options, data: DataJson) {
    let program_name_a = program_name("q5a", &params);
    let program_name_b = program_name("q5b", &params);
    let execution_name_a = |i: usize| format!("{program_name_a}-{i}");
    let n_messages_a = 50; // Maximum number of bids per auction
    let n_messages_b = data.auctions.len(); // Maximum number of auctions
    compile_and_setup(&program_name_a, params, options, n_messages_a);
    compile_and_setup(&program_name_b, params, options, n_messages_b);

    // SUBQUERY A
    // Group the bids per auction
    let bids_per_auction = group_bids_per_auction(&data, n_messages_a);

    // Collect input parameters per group, and sort each group by price.
    let mut inputs_per_auction: Vec<(
        u64,
        (
            Vec<MessageMetadata>,
            Bids,
            Vec<Signature>,
            Vec<SaltPoseidon>,
        ),
    )> = Vec::new();
    let mut messages_in_order = Vec::new();
    for (&auction, group) in bids_per_auction.iter() {
        let sorted = sort_bids_by_price(&group);
        // println!("auction: {}, bids: {:?}", auction, sorted.len());
        messages_in_order.extend(sorted.clone());
        let (msgs, bids, salts) = input::get_bids(&sorted, n_messages_a);
        let signatures = input::get_eddsa_poseidon_signatures(&sorted, n_messages_a);
        inputs_per_auction.push((auction, (msgs, bids, signatures, salts)));
    }

    // Execute subquery for each group.
    let mut outputs_a: HashMap<u64, (u64, HashPoseidon, SaltPoseidon)> = HashMap::new();
    for (i, (auction, (msgs, bids, signatures, salts))) in
        inputs_per_auction.into_iter().enumerate()
    {
        println!("> Executing for auction {} with {} bids", auction, bids.n);
        let publicKey = input::get_public_key_eddsa(&data);
        let outputSalt = input::generate_salt_poseidon();
        let inputs_a = match params.sig_variant {
            SigVariant::NoSig => Abi::Q5aPoseidonNoSig(Q5aPoseidonNoSigAbi {
                msgs,
                bids,
                salts,
                outputSalt: outputSalt.clone(),
            }),
            SigVariant::Sig => Abi::Q5aPoseidon(Q5aPoseidonAbi {
                publicKey,
                msgs,
                bids,
                signatures,
                outputSalt: outputSalt.clone(),
            }),
        };
        let outputs = execute(&program_name_a, &execution_name_a(i), inputs_a);

        let count_private = parse_u64(&outputs[0]);
        let auction_public = parse_u64(&outputs[1]);
        let hashed_count_public = parse_hash_poseidon(&outputs[2]);
        println!("For auction {}, count is {}", auction_public, count_private);
        // println!("Hashed count: {}", hashed_count_public);
        outputs_a.insert(
            auction_public,
            (count_private, hashed_count_public, outputSalt),
        );
    }
    let n_a = outputs_a.len();

    // SUBQUERY B
    // Sort the auctions by the highest bid count.
    let mut sorted_auctions = outputs_a
        .iter()
        .map(|(&a, &(c, ref h, ref s))| (a, c, h.clone(), s.clone()))
        .collect::<Vec<_>>();
    sorted_auctions.sort_by(|a, b| a.1.cmp(&b.1));

    // Collect input parameters.
    let (_, counts, hashes, salts): (Vec<u64>, Vec<u64>, Vec<HashPoseidon>, Vec<SaltPoseidon>) =
        multiunzip(sorted_auctions.into_iter());
    let u64s = input::get_u64s(&counts, n_messages_b);

    // Execute subquery.
    {
        let (valsHashes, salts) = input::get_hashes_salts(&hashes, &salts, n_messages_b);
        let inputs_b = match params.sig_variant {
            SigVariant::NoSig => Abi::Q5bPoseidonNoSig(Q5bPoseidonNoSigAbi {
                valsHashes,
                vals: u64s,
                salts,
            }),
            SigVariant::Sig => Abi::Q5bPoseidon(Q5bPoseidonAbi {
                valsHashes,
                vals: u64s,
                salts,
            }),
        };
        let outputs = execute(&program_name_b, &program_name_b, inputs_b);

        let result = parse_u64(&outputs[0]);
        println!("The highest bid count for an auction is {}", result);

        let auction = outputs_a
            .iter()
            .find(|&(_, &(c, _, _))| c == result)
            .expect("could not find auction");
        println!("The auction with the highest bid count is {}", auction.0);
    }

    let aggsig = aggregate_signatures(&messages_in_order, params);
    verification::q5(&data, n_a, aggsig, params, options);
}

#[allow(non_snake_case)]
pub fn query6(params: Params, options: Options, data: DataJson) {
    let program_name_a = program_name("q6a", &params);
    let program_name_b = program_name("q6b", &params);
    let execution_name_a = |i: usize| format!("{program_name_a}-{i}");
    let execution_name_b = |i: usize| format!("{program_name_b}-{i}");
    let n_messages_a = 50; // Maximum number of bids per auction
    let n_messages_b = 10; // Maximum number of auctions per seller
    compile_and_setup(&program_name_a, params, options, n_messages_a);
    compile_and_setup(&program_name_b, params, options, n_messages_b);

    // SUBQUERY A
    // Group the bids per auction
    let bids_per_auction = group_bids_per_auction(&data, n_messages_a);

    // Collect input parameters per group, and sort each group by price.
    let mut inputs_per_auction: Vec<(
        u64,
        (
            Vec<MessageMetadata>,
            Bids,
            Vec<Signature>,
            Vec<SaltPoseidon>,
        ),
    )> = Vec::new();
    let mut messages_in_order = Vec::new();
    for (&auction, group) in bids_per_auction.iter() {
        let sorted = sort_bids_by_price(&group);
        // println!("auction: {}, bids: {:?}", auction, sorted.len());
        messages_in_order.extend(sorted.clone());
        let (msgs, bids, salts) = input::get_bids(&sorted, n_messages_a);
        let signatures = input::get_eddsa_poseidon_signatures(&sorted, n_messages_a);
        inputs_per_auction.push((auction, (msgs, bids, signatures, salts)));
    }

    // Execute subquery for each group.
    let mut outputs_a: HashMap<u64, (u64, HashPoseidon, SaltPoseidon)> = HashMap::new();
    for (i, (auction, (msgs, bids, signatures, salts))) in
        inputs_per_auction.into_iter().enumerate()
    {
        println!("> Executing for auction {} with {} bids", auction, bids.n);
        let publicKey = input::get_public_key_eddsa(&data);
        let outputSalt = input::generate_salt_poseidon();
        let inputs_a = match params.sig_variant {
            SigVariant::NoSig => Abi::Q6aPoseidonNoSig(Q6aPoseidonNoSigAbi {
                msgs,
                bids,
                salts,
                outputSalt: outputSalt.clone(),
            }),
            SigVariant::Sig => Abi::Q6aPoseidon(Q6aPoseidonAbi {
                publicKey,
                msgs,
                bids,
                signatures,
                outputSalt: outputSalt.clone(),
            }),
        };
        let outputs = execute(&program_name_a, &execution_name_a(i), inputs_a);

        let price_private = parse_u64(&outputs[0]);
        let auction_public = parse_u64(&outputs[1]);
        let hashed_price_public = parse_hash_poseidon(&outputs[2]);
        println!(
            "For auction {}, max price is {}",
            auction_public, price_private
        );
        // println!("Hashed price: {}", hashed_price_public);
        outputs_a.insert(
            auction_public,
            (price_private, hashed_price_public, outputSalt),
        );
    }
    let n_a = outputs_a.len();

    // SUBQUERY B
    // Group the auctions per seller
    // Note: the verifier must check whether this happened correctly, using the public data.
    let auctions = outputs_a.keys().cloned().collect::<Vec<_>>();
    let auctions_per_seller = group_auctions_per_seller(&auctions, &data, n_messages_b);

    // Collect input parameters per group.
    let mut inputs_per_seller: Vec<(u64, (Vec<HashPoseidon>, U64s, Vec<SaltPoseidon>))> =
        Vec::new();
    for (&seller, auction_ids) in auctions_per_seller.iter() {
        println!("seller: {}, auction_ids: {:?}", seller, auction_ids);
        let (prices, hashes, salts): (Vec<u64>, Vec<HashPoseidon>, Vec<SaltPoseidon>) = auction_ids
            .iter()
            .map(|&auction_id| outputs_a.get(&auction_id).unwrap().clone())
            .multiunzip();
        let u64s = input::get_u64s(&prices, n_messages_b);
        inputs_per_seller.push((seller, (hashes, u64s, salts)));
    }

    // Execute subquery for each group.
    let mut outputs_b: HashMap<u64, u64> = HashMap::new();
    for (i, (seller, (hashes, u64s, salts))) in inputs_per_seller.into_iter().enumerate() {
        println!("> Executing for seller {} with {} values", seller, u64s.n);
        let (valsHashes, salts) = input::get_hashes_salts(&hashes, &salts, n_messages_b);
        let inputs_b = match params.sig_variant {
            SigVariant::NoSig => Abi::Q6bPoseidonNoSig(Q6bPoseidonNoSigAbi {
                valsHashes,
                vals: u64s,
                salts,
            }),
            SigVariant::Sig => Abi::Q6bPoseidon(Q6bPoseidonAbi {
                valsHashes,
                vals: u64s,
                salts,
            }),
        };
        let outputs = execute(&program_name_b, &execution_name_b(i), inputs_b);

        let result = parse_u64(&outputs[0]);
        println!("For seller {}, output is {}", seller, result);
        outputs_b.insert(seller, result);
    }
    let n_b = outputs_b.len();

    let aggsig = aggregate_signatures(&messages_in_order, params);
    verification::q6(&data, n_a, n_b, aggsig, params, options);
}

#[allow(non_snake_case)]
pub fn query7(params: Params, options: Options, data: DataJson) {
    let program_name = program_name("q7", &params);
    let n_messages = data.bids.len();
    compile_and_setup(&program_name, params, options, n_messages);

    let messages_by_price = sort_bids_by_price(&data.bids);
    let publicKey = input::get_public_key_eddsa(&data);
    let (msgs, bids, salts) = input::get_bids(&messages_by_price, n_messages);
    let signatures = input::get_eddsa_poseidon_signatures(&messages_by_price, n_messages);

    let inputs = match params.sig_variant {
        SigVariant::NoSig => Abi::Q7PoseidonNoSig(Q7PoseidonNoSigAbi { msgs, bids, salts }),
        SigVariant::Sig => Abi::Q7Poseidon(Q7PoseidonAbi {
            publicKey,
            msgs,
            bids,
            signatures,
        }),
    };

    let outputs = execute(&program_name, &program_name, inputs);

    let price_public = parse_u64(&outputs[0]);
    let auction_public = parse_u64(&outputs[1]);
    println!(
        "Highest price of {} for auction {}",
        price_public, auction_public
    );

    let aggsig = aggregate_signatures(&data.bids, params);
    verification::q7(&data, aggsig, params, options);
}

/// Parse output as u64.
fn parse_u64(output: &serde_json::Value) -> u64 {
    output.as_str().unwrap().parse::<u64>().unwrap()
}

// /// Parse output as field.
// -> note: use parse_hash_poseidon
// fn parse_field(output: &serde_json::Value) -> Fr {
//     datajson::utils::decimal_str_to_field(output.as_str().unwrap())
// }

/// Parse output as Poseidon hash.
fn parse_hash_poseidon(output: &serde_json::Value) -> HashPoseidon {
    output.as_str().unwrap().to_string()
}

/// Find auction by ID.
fn find_auction_by_id(data: &DataJson, auction_id: u64) -> Option<&Auction> {
    data.auctions.iter().find(|a| a.id == auction_id)
}

/// Sort bids by price.
fn sort_bids_by_price(bids: &Vec<SignedMessageJson>) -> Vec<SignedMessageJson> {
    let mut sorted = bids.clone();
    sorted.sort_by(|a, b| a.message.value.price.cmp(&b.message.value.price));
    sorted
}

/// Group the bids per auction.
fn group_bids_per_auction(
    data: &DataJson,
    n_messages: usize,
) -> BTreeMap<u64, Vec<SignedMessageJson>> {
    let mut bids_per_auction = BTreeMap::new();
    for bid in &data.bids {
        bids_per_auction
            .entry(bid.message.value.auction)
            .or_insert_with(Vec::new)
            .push(bid.clone());
        if bids_per_auction.len() >= n_messages {
            println!(
                "Reached maximum number of bids {} for auction {}",
                n_messages, bid.message.value.auction
            );
            break;
        }
    }
    bids_per_auction
}

/// Group the auctions per category.
fn group_auctions_per_category(
    auction_ids: &Vec<u64>,
    data: &DataJson,
    n_messages: usize,
) -> BTreeMap<u64, Vec<u64>> {
    let mut auctions_per_category = BTreeMap::new();
    for &auction_id in auction_ids {
        let auction = find_auction_by_id(&data, auction_id).expect("could not find auction");
        auctions_per_category
            .entry(auction.category)
            .or_insert_with(Vec::new)
            .push(auction_id);
        if auctions_per_category.len() >= n_messages {
            println!(
                "Reached maximum number of auctions {} for category {}",
                n_messages, auction.category
            );
            break;
        }
    }
    auctions_per_category
}

/// Group the auctions per seller.
fn group_auctions_per_seller(
    auction_ids: &Vec<u64>,
    data: &DataJson,
    n_messages: usize,
) -> BTreeMap<u64, Vec<u64>> {
    let mut auctions_per_seller = BTreeMap::new();
    for &auction_id in auction_ids {
        let auction = find_auction_by_id(&data, auction_id).expect("could not find auction");
        auctions_per_seller
            .entry(auction.seller)
            .or_insert_with(Vec::new)
            .push(auction_id);
        if auctions_per_seller.len() >= n_messages {
            println!(
                "Reached maximum number of auctions {} for seller {}",
                n_messages, auction.seller
            );
            break;
        }
    }
    auctions_per_seller
}

/// Compile and setup program.
fn compile_and_setup(program_name: &str, params: Params, options: Options, n_messages: usize) {
    if !options.skip_compilation {
        compile(&program_name, options.debug, params, n_messages);
        setup(&program_name);
    }
}

/// Execute program.
fn execute(program_name: &str, execution_name: &str, inputs: Abi) -> Vec<serde_json::Value> {
    let outputs = compute_witness(&program_name, &execution_name, inputs);
    generate_proof(&program_name, &execution_name);
    outputs
}

/// Aggregate signatures.
fn aggregate_signatures(
    messages: &Vec<SignedMessageJson>,
    params: Params,
) -> Option<BLSAggregateSignature> {
    if params.bls == Bls::Yes {
        aggregate_bls_signatures(messages)
    } else {
        None
    }
}
