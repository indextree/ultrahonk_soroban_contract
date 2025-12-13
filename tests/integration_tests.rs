use soroban_sdk::{Address, Bytes, Env};
use ultrahonk_soroban_contract::{preprocess_vk_json, UltraHonkVerifierContract};

const CONTRACT_WASM: &[u8] = include_bytes!("../out/ultrahonk_soroban_contract.wasm");

fn vk_bytes_from_json(env: &Env, json: &str) -> Bytes {
    let vk_blob = preprocess_vk_json(json).expect("valid vk json");
    assert_eq!(vk_blob.len(), 1824, "unexpected VK byte length");
    let bytes = Bytes::from_slice(env, &vk_blob);
    assert_eq!(bytes.len(), 1824, "unexpected Bytes len");
    bytes
}

macro_rules! build_artifacts {
    ($vk:expr, $proof:expr, $pub_inputs:expr) => {{
        let vk_fields_json: &str = include_str!($vk);
        let proof_bin: &[u8] = include_bytes!($proof);
        let pub_inputs_bin: &[u8] = include_bytes!($pub_inputs);

        let env = Env::default();
        env.budget().reset_unlimited();

        let vk_bytes = vk_bytes_from_json(&env, vk_fields_json);
        const PROOF_NUM_FIELDS: u32 = 440;
        assert!(pub_inputs_bin.len() % 32 == 0);
        let num_inputs = (pub_inputs_bin.len() / 32) as u32;
        let total_fields = PROOF_NUM_FIELDS + num_inputs;
        let mut packed: Vec<u8> = Vec::with_capacity(4 + pub_inputs_bin.len() + proof_bin.len());
        packed.extend_from_slice(&total_fields.to_be_bytes());
        packed.extend_from_slice(pub_inputs_bin);
        packed.extend_from_slice(proof_bin);
        let proof_bytes: Bytes = Bytes::from_slice(&env, &packed);

        let contract_id = env.register(UltraHonkVerifierContract, ());
        (env, vk_bytes, proof_bytes, contract_id)
    }};
}

fn build_simple_artifacts() -> (Env, Bytes, Bytes, soroban_sdk::Address) {
    build_artifacts!(
        "simple_circuit/target/vk_fields.json",
        "simple_circuit/target/proof",
        "simple_circuit/target/public_inputs"
    )
}

fn build_simple_poseidon2_artifacts() -> (Env, Bytes, Bytes, soroban_sdk::Address) {
    build_artifacts!(
        "simple_circuit/target_poseidon2/vk_fields.json",
        "simple_circuit/target_poseidon2/proof",
        "simple_circuit/target_poseidon2/public_inputs"
    )
}

#[test]
fn verify_simple_circuit_proof_succeeds() {
    let (env, vk_bytes, proof_bytes, contract_id) = build_simple_artifacts();
    env.as_contract(&contract_id, || {
        UltraHonkVerifierContract::verify_proof(
            env.clone(),
            vk_bytes.clone(),
            proof_bytes.clone(),
        )
    })
    .expect("verification should succeed");
}

#[test]
fn verify_simple_circuit_poseidon2_proof_succeeds() {
    let (env, vk_bytes, proof_bytes, contract_id) = build_simple_poseidon2_artifacts();
    env.as_contract(&contract_id, || {
        UltraHonkVerifierContract::verify_proof_poseidon2(env.clone(), vk_bytes, proof_bytes)
    })
    .expect("verification should succeed (poseidon2)");
}

#[test]
fn verify_fib_chain_proof_succeeds() {
    let vk_fields_json: &str = include_str!("fib_chain/target/vk_fields.json");
    let proof_bin: &[u8] = include_bytes!("fib_chain/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("fib_chain/target/public_inputs");

    let env = Env::default();
    env.budget().reset_unlimited();

    // Prepare inputs
    let vk_bytes = vk_bytes_from_json(&env, vk_fields_json);
    const PROOF_NUM_FIELDS: u32 = 440;
    assert!(pub_inputs_bin.len() % 32 == 0);
    let num_inputs = (pub_inputs_bin.len() / 32) as u32;
    let total_fields = PROOF_NUM_FIELDS + num_inputs;
    let mut packed: Vec<u8> = Vec::with_capacity(4 + pub_inputs_bin.len() + proof_bin.len());
    packed.extend_from_slice(&total_fields.to_be_bytes());
    packed.extend_from_slice(pub_inputs_bin);
    packed.extend_from_slice(proof_bin);
    let proof_bytes: Bytes = Bytes::from_slice(&env, &packed);

    // Register to obtain a contract ID for storage namespace
    let contract_id = env.register(UltraHonkVerifierContract, ());

    // Verify should succeed and not panic
    env.as_contract(&contract_id, || {
        UltraHonkVerifierContract::verify_proof(env.clone(), vk_bytes, proof_bytes)
    })
    .expect("verification should succeed");
}

#[test]
fn print_budget_for_deploy_and_verify() {
    let vk_fields_json: &str = include_str!("simple_circuit/target/vk_fields.json");
    let proof_bin: &[u8] = include_bytes!("simple_circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("simple_circuit/target/public_inputs");

    let env = Env::default();

    // Measure deploy (upload wasm + register) budget usage.
    env.budget().reset_unlimited();
    let wasm_bytes = Bytes::from_slice(&env, CONTRACT_WASM);
    let contract_id = env.register_contract_wasm(None, wasm_bytes);
    println!("=== Deploy budget usage ===");
    env.cost_estimate().budget().print();

    // Prepare proof inputs
    let vk_bytes = vk_bytes_from_json(&env, vk_fields_json);
    const PROOF_NUM_FIELDS: u32 = 440;
    assert!(pub_inputs_bin.len() % 32 == 0);
    let num_inputs = (pub_inputs_bin.len() / 32) as u32;
    let total_fields = PROOF_NUM_FIELDS + num_inputs;
    let mut packed: Vec<u8> = Vec::with_capacity(4 + pub_inputs_bin.len() + proof_bin.len());
    packed.extend_from_slice(&total_fields.to_be_bytes());
    packed.extend_from_slice(pub_inputs_bin);
    packed.extend_from_slice(proof_bin);
    let proof_bytes: Bytes = Bytes::from_slice(&env, &packed);

    // Measure verify_proof invocation budget usage in isolation.
    env.budget().reset_unlimited();
    let vk_for_keccak = vk_bytes.clone();
    let proof_for_keccak = proof_bytes.clone();
    env.as_contract(&contract_id, || {
        UltraHonkVerifierContract::verify_proof(env.clone(), vk_for_keccak, proof_for_keccak)
    })
    .expect("verification should succeed");
    println!("=== verify_proof budget usage ===");
    env.cost_estimate().budget().print();

    let poseidon_vk_fields_json: &str =
        include_str!("simple_circuit/target_poseidon2/vk_fields.json");
    let poseidon_proof_bin: &[u8] = include_bytes!("simple_circuit/target_poseidon2/proof");
    let poseidon_pub_inputs_bin: &[u8] =
        include_bytes!("simple_circuit/target_poseidon2/public_inputs");
    let poseidon_vk_bytes = vk_bytes_from_json(&env, poseidon_vk_fields_json);
    assert!(poseidon_pub_inputs_bin.len() % 32 == 0);
    let poseidon_num_inputs = (poseidon_pub_inputs_bin.len() / 32) as u32;
    let poseidon_total_fields = PROOF_NUM_FIELDS + poseidon_num_inputs;
    let mut poseidon_packed: Vec<u8> = Vec::with_capacity(
        4 + poseidon_pub_inputs_bin.len() + poseidon_proof_bin.len(),
    );
    poseidon_packed.extend_from_slice(&poseidon_total_fields.to_be_bytes());
    poseidon_packed.extend_from_slice(poseidon_pub_inputs_bin);
    poseidon_packed.extend_from_slice(poseidon_proof_bin);
    let poseidon_proof_bytes: Bytes = Bytes::from_slice(&env, &poseidon_packed);

    env.budget().reset_unlimited();
    env.as_contract(&contract_id, || {
        UltraHonkVerifierContract::verify_proof_poseidon2(
            env.clone(),
            poseidon_vk_bytes,
            poseidon_proof_bytes,
        )
    })
    .expect("poseidon2 verification should succeed");
    println!("=== verify_proof_poseidon2 budget usage ===");
    env.cost_estimate().budget().print();
}
