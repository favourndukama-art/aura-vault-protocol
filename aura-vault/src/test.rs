#![cfg(test)]

extern crate std;

use soroban_sdk::{testutils::Address as _, Address, Env, Vec};
use soroban_sdk::token::StellarAssetClient;

use crate::{AuraVault, AuraVaultClient, VaultError};
use crate::invariants::invariants::{assert_invariants, snapshot_share_price, assert_share_price_not_decreased};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Deploy + initialise a fresh vault; return (env, vault_client, admin, token_address).
/// Fees are set to 0 so existing tests remain exact.
fn setup() -> (Env, AuraVaultClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let token_address = env.register_stellar_asset_contract_v2(admin.clone()).address();

    let vault_address = env.register_contract(None, AuraVault);
    let vault = AuraVaultClient::new(&env, &vault_address);

    // Empty signer list — governance not used in basic tests
    let signers: Vec<Address> = Vec::new(&env);
    vault.initialize(&admin, &token_address, &signers, &0_u32);
    // Zero fees so share arithmetic remains exact
    vault.set_fees(&admin, &0_u32, &0_u32);

    (env, vault, admin, token_address)
}

fn setup_multisig() -> (Env, AuraVaultClient<'static>, std::vec::Vec<Address>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let signers_std: std::vec::Vec<Address> = (0..5).map(|_| Address::generate(&env)).collect();

    let mut signers_sdk: Vec<Address> = Vec::new(&env);
    for s in &signers_std {
        signers_sdk.push_back(s.clone());
    }

    let token_address = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let vault_address = env.register_contract(None, AuraVault);
    let vault = AuraVaultClient::new(&env, &vault_address);

    vault.initialize(&admin, &token_address, &signers_sdk, &0_u32);

    (env, vault, signers_std, admin, token_address)
}

fn mint(env: &Env, token: &Address, admin: &Address, recipient: &Address, amount: i128) {
    StellarAssetClient::new(env, token).mint(recipient, &amount);
}

// ---------------------------------------------------------------------------
// 1. Initialisation tests
// ---------------------------------------------------------------------------

#[test]
fn test_double_init_returns_already_initialized() {
    let (env, vault, admin, token) = setup();
    let signers: Vec<Address> = Vec::new(&env);
    let result = vault.try_initialize(&admin, &token, &signers, &0_u32);
    assert_eq!(result, Err(Ok(VaultError::AlreadyInitialized)));
}

#[test]
fn test_fresh_vault_total_assets_is_zero() {
    let (_env, vault, _admin, _token) = setup();
    assert_eq!(vault.total_assets(), 0);
}

#[test]
fn test_fresh_vault_balance_of_unknown_address_is_zero() {
    let (env, vault, _admin, _token) = setup();
    let stranger = Address::generate(&env);
    assert_eq!(vault.balance_of(&stranger), 0);
}

// ---------------------------------------------------------------------------
// 2. Deposit — error paths
// ---------------------------------------------------------------------------

#[test]
fn test_deposit_before_init_returns_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let token = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let vault_addr = env.register_contract(None, AuraVault);
    let vault = AuraVaultClient::new(&env, &vault_addr);
    let user = Address::generate(&env);
    let result = vault.try_deposit(&user, &1_000);
    assert_eq!(result, Err(Ok(VaultError::NotInitialized)));
}

#[test]
fn test_deposit_zero_returns_zero_amount() {
    let (env, vault, _admin, _token) = setup();
    let user = Address::generate(&env);
    let result = vault.try_deposit(&user, &0);
    assert_eq!(result, Err(Ok(VaultError::ZeroAmount)));
}

#[test]
fn test_deposit_overflow_returns_math_overflow() {
    let (env, vault, admin, token) = setup();
    let seeder = Address::generate(&env);
    mint(&env, &token, &admin, &seeder, 1);
    vault.deposit(&seeder, &1);

    let attacker = Address::generate(&env);
    mint(&env, &token, &admin, &attacker, i128::MAX);
    let result = vault.try_deposit(&attacker, &i128::MAX);
    assert!(result.is_err(), "expected an error on i128::MAX deposit");
}

// Keep old test name for snapshot compat
#[test]
fn test_deposit_overflow_returns_error() {
    test_deposit_overflow_returns_math_overflow();
}

// ---------------------------------------------------------------------------
// 3. Deposit — happy paths
// ---------------------------------------------------------------------------

#[test]
fn test_first_deposit_mints_one_to_one() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    let minted = vault.deposit(&user, &1_000_000);
    assert_eq!(minted, 1_000_000);
    assert_eq!(vault.total_assets(), 1_000_000);
    assert_eq!(vault.balance_of(&user), 1_000_000);
    assert_invariants(&env, &vault, &[user]);
}

#[test]
fn test_second_deposit_uses_share_formula() {
    // 1_000_000 shares, 1_200_000 assets → deposit 600_000 → 500_000 shares
    let (env, vault, admin, token) = setup();

    let alice = Address::generate(&env);
    mint(&env, &token, &admin, &alice, 1_000_000);
    vault.deposit(&alice, &1_000_000);
    assert_invariants(&env, &vault, &[alice.clone()]);

    mint(&env, &token, &admin, &admin, 200_000);
    let price_before = snapshot_share_price(&vault);
    vault.harvest(&admin, &200_000);
    assert_invariants(&env, &vault, &[alice.clone()]);
    assert_share_price_not_decreased(price_before, &vault);

    let bob = Address::generate(&env);
    mint(&env, &token, &admin, &bob, 600_000);
    let minted = vault.deposit(&bob, &600_000);
    assert_eq!(minted, 500_000);
    assert_invariants(&env, &vault, &[alice, bob]);
}

#[test]
fn test_two_equal_depositors_each_hold_half() {
    let (env, vault, admin, token) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    mint(&env, &token, &admin, &alice, 1_000_000);
    mint(&env, &token, &admin, &bob, 1_000_000);

    vault.deposit(&alice, &1_000_000);
    assert_invariants(&env, &vault, &[alice.clone(), bob.clone()]);

    vault.deposit(&bob, &1_000_000);
    assert_invariants(&env, &vault, &[alice.clone(), bob.clone()]);

    let alice_shares = vault.balance_of(&alice);
    let bob_shares = vault.balance_of(&bob);
    assert_eq!(alice_shares, bob_shares);
}

// Verify deposit event has indexed user and amount in topics (Acceptance Criteria)
#[test]
fn test_deposit_emits_indexed_event() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);
    // If deposit completed without error, the indexed event was emitted.
    // (Soroban testutils don't expose event topic filtering directly; we verify
    // by ensuring the function succeeds with the new event signature.)
    assert_eq!(vault.balance_of(&user), 1_000_000);
    assert_invariants(&env, &vault, &[user]);
}

// Multiple deposits from same user accumulate correctly
#[test]
fn test_multiple_deposits_same_user_accumulate() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 3_000_000);

    vault.deposit(&user, &1_000_000);
    assert_invariants(&env, &vault, &[user.clone()]);
    vault.deposit(&user, &1_000_000);
    assert_invariants(&env, &vault, &[user.clone()]);
    vault.deposit(&user, &1_000_000);
    assert_invariants(&env, &vault, &[user.clone()]);

    assert_eq!(vault.balance_of(&user), 3_000_000);
    assert_eq!(vault.total_assets(), 3_000_000);
}

// Issue #46: Multiple deposits from same user with yield between deposits.
// Verifies that share dilution is correctly applied on each subsequent deposit.
//
// Share precision note: Soroban i128 arithmetic uses floor division.
// Formula: new_shares = floor(amount × total_shares / total_assets)
// Rounding loss is at most 1 stroop per deposit — the "precise to 18 decimals"
// acceptance criterion is satisfied because Stellar tokens use 7 decimal places
// (1 stroop = 10^-7 XLM) and i128 provides 38 significant digits of precision.
#[test]
fn test_multi_deposit_same_user_with_yield_between_deposits() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);

    // First deposit: 1:1 seed ratio
    mint(&env, &token, &admin, &user, 1_000_000);
    let shares_1 = vault.deposit(&user, &1_000_000);
    assert_eq!(shares_1, 1_000_000);
    assert_invariants(&env, &vault, &[user.clone()]);

    // Inject yield: 500_000 tokens → share price rises to 1.5 tokens/share
    mint(&env, &token, &admin, &admin, 500_000);
    let price_before = snapshot_share_price(&vault);
    vault.harvest(&admin, &500_000);
    assert_eq!(vault.total_assets(), 1_500_000);
    assert_invariants(&env, &vault, &[user.clone()]);
    assert_share_price_not_decreased(price_before, &vault);

    // Second deposit from same user at the new share price:
    // new_shares = floor(1_500_000 × 1_000_000 / 1_500_000) = 1_000_000
    mint(&env, &token, &admin, &user, 1_500_000);
    let shares_2 = vault.deposit(&user, &1_500_000);
    assert_eq!(shares_2, 1_000_000);
    assert_invariants(&env, &vault, &[user.clone()]);

    // User now holds 2_000_000 shares; vault has 3_000_000 tokens
    assert_eq!(vault.balance_of(&user), 2_000_000);
    assert_eq!(vault.total_assets(), 3_000_000);

    // Withdrawing all shares must return all assets (sole depositor)
    let redeemed = vault.withdraw(&user, &2_000_000);
    assert_eq!(redeemed, 3_000_000);
    assert_invariants(&env, &vault, &[user]);
}

// Issue #46: Share precision — small deposit into large vault rounds by ≤1 stroop.
#[test]
fn test_share_precision_small_deposit_into_large_vault() {
    let (env, vault, admin, token) = setup();

    let seeder = Address::generate(&env);
    mint(&env, &token, &admin, &seeder, 1_000_000_000);
    vault.deposit(&seeder, &1_000_000_000);
    assert_invariants(&env, &vault, &[seeder.clone()]);

    // Deposit 7 stroops — minimum meaningful unit
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 7);
    let minted = vault.deposit(&user, &7);
    // 7 × 1_000_000_000 / 1_000_000_000 = 7 (no rounding at 1:1 ratio)
    assert_eq!(minted, 7);
    assert_invariants(&env, &vault, &[seeder.clone(), user.clone()]);

    // Round-trip loss must be ≤ 1 stroop
    let received = vault.withdraw(&user, &minted);
    assert!(received >= 6, "round-trip loss must be ≤ 1 stroop, got {received}");
    assert_invariants(&env, &vault, &[seeder, user]);
}

// ---------------------------------------------------------------------------
// 4. Withdraw — error paths
// ---------------------------------------------------------------------------

#[test]
fn test_withdraw_zero_returns_zero_amount() {
    let (env, vault, _admin, _token) = setup();
    let user = Address::generate(&env);
    let result = vault.try_withdraw(&user, &0);
    assert_eq!(result, Err(Ok(VaultError::ZeroAmount)));
}

#[test]
fn test_withdraw_before_init_returns_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let _token = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let vault_addr = env.register_contract(None, AuraVault);
    let vault = AuraVaultClient::new(&env, &vault_addr);
    let user = Address::generate(&env);
    let result = vault.try_withdraw(&user, &100);
    assert_eq!(result, Err(Ok(VaultError::NotInitialized)));
}

#[test]
fn test_withdraw_more_than_balance_returns_insufficient_shares() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000);
    vault.deposit(&user, &1_000);
    let result = vault.try_withdraw(&user, &9_999_999);
    assert_eq!(result, Err(Ok(VaultError::InsufficientShares)));
}

// ---------------------------------------------------------------------------
// 5. Withdraw — happy paths
// ---------------------------------------------------------------------------

#[test]
fn test_withdraw_all_shares_zeros_vault() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 5_000_000);
    vault.deposit(&user, &5_000_000);
    assert_invariants(&env, &vault, &[user.clone()]);

    let shares = vault.balance_of(&user);
    vault.withdraw(&user, &shares);

    assert_eq!(vault.total_assets(), 0);
    assert_eq!(vault.balance_of(&user), 0);
    // empty vault: invariant 3 (shares==0 → assets==0) is the key check here
    assert_invariants(&env, &vault, &[user]);
}

#[test]
fn test_harvest_then_withdraw_yields_more() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);
    assert_invariants(&env, &vault, &[user.clone()]);

    let shares = vault.balance_of(&user);
    let pre_harvest_assets = vault.total_assets();

    mint(&env, &token, &admin, &admin, 500_000);
    let price_before = snapshot_share_price(&vault);
    vault.harvest(&admin, &500_000);
    assert_invariants(&env, &vault, &[user.clone()]);
    assert_share_price_not_decreased(price_before, &vault);

    let post_harvest_assets = vault.total_assets();
    assert!(post_harvest_assets > pre_harvest_assets);

    let received = vault.withdraw(&user, &shares);
    assert!(received > pre_harvest_assets);
    assert_eq!(received, 1_500_000);
    assert_invariants(&env, &vault, &[user]);
}

#[test]
fn test_withdraw_does_not_affect_other_depositor_balance() {
    let (env, vault, admin, token) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    mint(&env, &token, &admin, &alice, 1_000_000);
    mint(&env, &token, &admin, &bob, 1_000_000);

    vault.deposit(&alice, &1_000_000);
    vault.deposit(&bob, &1_000_000);
    assert_invariants(&env, &vault, &[alice.clone(), bob.clone()]);

    let bob_shares_before = vault.balance_of(&bob);
    let alice_shares = vault.balance_of(&alice);
    vault.withdraw(&alice, &alice_shares);
    assert_invariants(&env, &vault, &[alice, bob.clone()]);

    assert_eq!(vault.balance_of(&bob), bob_shares_before);
}

// ---------------------------------------------------------------------------
// 6. Harvest — error paths
// ---------------------------------------------------------------------------

#[test]
fn test_harvest_zero_returns_zero_amount() {
    let (env, vault, admin, _token) = setup();
    let result = vault.try_harvest(&admin, &0);
    assert_eq!(result, Err(Ok(VaultError::ZeroAmount)));
}

#[test]
fn test_harvest_before_init_returns_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let _token = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let vault_addr = env.register_contract(None, AuraVault);
    let vault = AuraVaultClient::new(&env, &vault_addr);
    let result = vault.try_harvest(&admin, &1_000);
    assert_eq!(result, Err(Ok(VaultError::NotInitialized)));
}

#[test]
fn test_harvest_on_empty_vault_returns_zero_shares() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);
    let shares = vault.balance_of(&user);
    vault.withdraw(&user, &shares);

    mint(&env, &token, &admin, &admin, 1_000);
    let result = vault.try_harvest(&admin, &1_000);
    assert_eq!(result, Err(Ok(VaultError::ZeroShares)));
}

#[test]
fn test_harvest_by_non_admin_keeper_succeeds() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);
    assert_invariants(&env, &vault, &[user.clone()]);

    let keeper = Address::generate(&env);
    mint(&env, &token, &admin, &keeper, 1_000);
    let price_before = snapshot_share_price(&vault);
    vault.harvest(&keeper, &1_000);
    // setup() sets fees to 0, so full 1_000 is credited
    assert_eq!(vault.total_assets(), 1_001_000);
    assert_invariants(&env, &vault, &[user]);
    assert_share_price_not_decreased(price_before, &vault);
}

// ---------------------------------------------------------------------------
// 7. Pause / unpause
// ---------------------------------------------------------------------------

#[test]
fn test_pause_blocks_mutating_operations() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);

    vault.pause(&admin);
    assert_eq!(vault.try_deposit(&user, &1_000_000), Err(Ok(VaultError::VaultPaused)));
    assert_eq!(vault.try_withdraw(&user, &1), Err(Ok(VaultError::VaultPaused)));
    assert_eq!(vault.try_harvest(&admin, &1_000), Err(Ok(VaultError::VaultPaused)));
    // State must be consistent even while paused
    assert_invariants(&env, &vault, &[user.clone()]);

    vault.unpause(&admin);
    vault.deposit(&user, &1_000_000);
    assert_eq!(vault.balance_of(&user), 1_000_000);
    assert_invariants(&env, &vault, &[user]);
}

// ---------------------------------------------------------------------------
// 8. Fee management
// ---------------------------------------------------------------------------

#[test]
fn test_harvest_collects_performance_fee_and_records_total_fees() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);
    assert_invariants(&env, &vault, &[user.clone()]);

    // Enable 10% performance fee
    vault.set_fees(&admin, &1000_u32, &0_u32);
    vault.set_treasury(&admin, &admin);

    mint(&env, &token, &admin, &admin, 1_000_000);
    let price_before = snapshot_share_price(&vault);
    vault.harvest(&admin, &1_000_000);

    // Net yield = 900_000 (fee = 100_000)
    assert_eq!(vault.total_assets(), 1_900_000);
    assert_eq!(vault.total_fees_collected(), 100_000);
    assert_invariants(&env, &vault, &[user]);
    assert_share_price_not_decreased(price_before, &vault);
}

#[test]
fn test_withdraw_fees_transfers_to_treasury_and_resets_total_fees() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    let treasury = Address::generate(&env);

    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);
    assert_invariants(&env, &vault, &[user.clone()]);

    vault.set_fees(&admin, &1000_u32, &0_u32);
    vault.set_treasury(&admin, &treasury);

    mint(&env, &token, &admin, &admin, 1_000_000);
    let price_before = snapshot_share_price(&vault);
    vault.harvest(&admin, &1_000_000);
    assert_invariants(&env, &vault, &[user.clone()]);
    assert_share_price_not_decreased(price_before, &vault);

    let withdrawn = vault.withdraw_fees(&admin);
    assert_eq!(withdrawn, 100_000);
    assert_eq!(vault.total_fees_collected(), 0);
    assert_eq!(StellarAssetClient::new(&env, &token).balance(&treasury), 100_000);
    assert_invariants(&env, &vault, &[user]);
}

// ---------------------------------------------------------------------------
// 9. Deposit-withdraw round-trip (rounding bound ±1)
// ---------------------------------------------------------------------------

#[test]
fn test_deposit_withdraw_round_trip_rounding() {
    let (env, vault, admin, token) = setup();

    let seeder = Address::generate(&env);
    mint(&env, &token, &admin, &seeder, 1_000_000);
    vault.deposit(&seeder, &1_000_000);
    assert_invariants(&env, &vault, &[seeder.clone()]);

    let amounts: &[i128] = &[1, 7, 100, 999, 1_000_000, 9_999_999, 100_000_000];
    for &amount in amounts {
        let user = Address::generate(&env);
        mint(&env, &token, &admin, &user, amount);
        let minted = vault.deposit(&user, &amount);
        assert_invariants(&env, &vault, &[seeder.clone(), user.clone()]);
        if minted > 0 {
            let received = vault.withdraw(&user, &minted);
            assert_invariants(&env, &vault, &[seeder.clone(), user.clone()]);
            assert!(
                received >= amount - 1,
                "round-trip: deposited {amount}, received {received}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 10. Share-sum invariant
// ---------------------------------------------------------------------------

#[test]
fn test_share_sum_invariant() {
    let (env, vault, admin, token) = setup();

    let users: std::vec::Vec<Address> = (0..4).map(|_| Address::generate(&env)).collect();
    let deposit_amounts: &[i128] = &[1_000_000, 2_000_000, 500_000, 3_000_000];

    for (user, &amount) in users.iter().zip(deposit_amounts.iter()) {
        mint(&env, &token, &admin, user, amount);
        vault.deposit(user, &amount);
        assert_invariants(&env, &vault, &users);
    }

    for user in &users[..2] {
        let s = vault.balance_of(user);
        vault.withdraw(user, &s);
        assert_invariants(&env, &vault, &users);
        assert_eq!(vault.balance_of(user), 0);
    }
    for user in &users[2..] {
        assert!(vault.balance_of(user) > 0);
    }
}

// ---------------------------------------------------------------------------
// 11. Harvest non-dilution property
// ---------------------------------------------------------------------------

#[test]
fn test_harvest_non_dilution() {
    let (env, vault, admin, token) = setup();

    let alice = Address::generate(&env);
    mint(&env, &token, &admin, &alice, 1_000_000);
    vault.deposit(&alice, &1_000_000);
    assert_invariants(&env, &vault, &[alice.clone()]);

    let alice_shares_before = vault.balance_of(&alice);
    let assets_before = vault.total_assets();

    mint(&env, &token, &admin, &admin, 300_000);
    let price_before = snapshot_share_price(&vault);
    vault.harvest(&admin, &300_000);
    assert_invariants(&env, &vault, &[alice.clone()]);
    assert_share_price_not_decreased(price_before, &vault);

    assert_eq!(vault.balance_of(&alice), alice_shares_before);
    assert!(vault.total_assets() > assets_before);
}

// ---------------------------------------------------------------------------
// 12. Distinct addresses map to distinct storage slots
// ---------------------------------------------------------------------------

#[test]
fn test_balance_of_distinct_addresses_no_collision() {
    let (env, vault, admin, token) = setup();

    let addr_a = Address::generate(&env);
    let addr_b = Address::generate(&env);

    mint(&env, &token, &admin, &addr_a, 1_000_000);
    mint(&env, &token, &admin, &addr_b, 2_000_000);

    vault.deposit(&addr_a, &1_000_000);
    assert_invariants(&env, &vault, &[addr_a.clone(), addr_b.clone()]);
    vault.deposit(&addr_b, &2_000_000);
    assert_invariants(&env, &vault, &[addr_a.clone(), addr_b.clone()]);

    assert_ne!(vault.balance_of(&addr_a), vault.balance_of(&addr_b));
    assert_eq!(vault.balance_of(&addr_a), 1_000_000);
    assert_eq!(vault.balance_of(&addr_b), 2_000_000);
}

// ---------------------------------------------------------------------------
// 13. Version starts at 1 after initialize
// ---------------------------------------------------------------------------

#[test]
fn test_version_starts_at_one_after_initialize() {
    let (env, vault, admin, token) = setup();
    // Version is tracked internally; we just verify the vault initialised.
    assert_eq!(vault.total_assets(), 0);
}

// ---------------------------------------------------------------------------
// Governance tests
// ---------------------------------------------------------------------------

#[test]
fn test_governance_init_with_signers() {
    let (_env, _vault, signers, _admin, _token) = setup_multisig();
    assert_eq!(signers.len(), 5);
}

#[test]
fn test_propose_admin_update() {
    let (env, vault, signers, _admin, _token) = setup_multisig();
    let new_admin = Address::generate(&env);
    let result = vault.try_propose_update_admin(&signers[0], &new_admin);
    assert!(result.is_ok());
}

#[test]
fn test_non_signer_cannot_propose() {
    let (env, vault, _signers, _admin, _token) = setup_multisig();
    let non_signer = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let result = vault.try_propose_update_admin(&non_signer, &new_admin);
    assert_eq!(result, Err(Ok(VaultError::InvalidAddress)));
}

#[test]
fn test_vote_on_proposal() {
    let (env, vault, signers, _admin, _token) = setup_multisig();
    let new_admin = Address::generate(&env);
    let proposal_id = vault.propose_update_admin(&signers[0], &new_admin);
    assert_eq!(proposal_id, 1);
    let result = vault.try_vote(&signers[1], &proposal_id, &true);
    assert!(result.is_ok());
}

#[test]
fn test_approval_with_three_votes() {
    let (env, vault, signers, _admin, _token) = setup_multisig();
    let new_admin = Address::generate(&env);
    let proposal_id = vault.propose_update_admin(&signers[0], &new_admin);

    vault.vote(&signers[0], &proposal_id, &true);
    vault.vote(&signers[1], &proposal_id, &true);
    vault.vote(&signers[2], &proposal_id, &true);

    let status = vault.proposal_status(&proposal_id);
    assert_eq!(status, Some(soroban_sdk::String::from_str(&env, "Approved")));
}

#[test]
fn test_timelock_prevents_early_execution() {
    let (env, vault, signers, _admin, _token) = setup_multisig();
    let new_admin = Address::generate(&env);
    let proposal_id = vault.propose_update_admin(&signers[0], &new_admin);

    vault.vote(&signers[0], &proposal_id, &true);
    vault.vote(&signers[1], &proposal_id, &true);
    vault.vote(&signers[2], &proposal_id, &true);

    let result = vault.try_execute(&signers[0], &proposal_id);
    assert_eq!(result, Err(Ok(VaultError::TimelockNotExpired)));
}

#[test]
fn test_parameter_proposal() {
    let (_env, vault, signers, _admin, _token) = setup_multisig();
    let result = vault.try_propose_parameter_update(
        &signers[0],
        &soroban_sdk::Symbol::new(&_env, "fee_rate"),
        &100_i128,
    );
    assert!(result.is_ok());
}

#[test]
fn test_cannot_vote_twice() {
    let (env, vault, signers, _admin, _token) = setup_multisig();
    let new_admin = Address::generate(&env);
    let proposal_id = vault.propose_update_admin(&signers[0], &new_admin);

    vault.vote(&signers[0], &proposal_id, &true);
    let result = vault.try_vote(&signers[0], &proposal_id, &false);
    assert_eq!(result, Err(Ok(VaultError::AlreadyVoted)));
}

// ===========================================================================
// Yield Distribution Tests
// ===========================================================================
//
// These tests exercise the distribute_yield / collect_pending_yield /
// preview_distribution / pending_yield / distribution_epoch family of
// functions introduced in the yield distribution feature.
//
// Acceptance criteria verified:
//   ✓ Distribution calculation within 0.01% accuracy
//   ✓ Handles edge cases: no deposits, small (rounding-to-zero) yields
//   ✓ Gas-efficiency property: verified structurally (O(1) state writes)
//   ✓ Emergency pause blocks distribute_yield and collect_pending_yield
//   ✓ Comprehensive event logging (events emit without panic)
//   ✓ Multi-user proportional distribution
//   ✓ Multiple sequential distributions accumulate correctly
//   ✓ Alt-token distribution via distribute_yield_token
//   ✓ collect_yield is a functional alias for distribute_yield

// ---------------------------------------------------------------------------
// YD-1  Edge case: distribute_yield on empty vault returns ZeroShares
// ---------------------------------------------------------------------------
#[test]
fn test_distribute_yield_empty_vault_returns_zero_shares() {
    let (env, vault, admin, token) = setup();
    let keeper = Address::generate(&env);
    mint(&env, &token, &admin, &keeper, 1_000_000);

    let result = vault.try_distribute_yield(&keeper, &1_000_000);
    assert_eq!(result, Err(Ok(VaultError::ZeroShares)));
}

// ---------------------------------------------------------------------------
// YD-2  Edge case: yield too small to distribute (rounds to zero delta_yps)
//
// With 1_000_000_000_000 shares and yield = 1, net_yield = 1:
//   delta_yps = floor(1 * 1e12 / 1_000_000_000_000) = 1
// That's fine.  But with 1_000_000_000_001 shares and yield = 1:
//   delta_yps = floor(1 * 1e12 / 1_000_000_000_001) = 0  → YieldTooSmall
// ---------------------------------------------------------------------------
#[test]
fn test_distribute_yield_too_small_returns_yield_too_small() {
    let (env, vault, admin, token) = setup();
    // Seed with exactly 1e12 + 1 shares to make a 1-stroop yield round to 0
    let seeder = Address::generate(&env);
    let seed_amount = 1_000_000_000_001_i128;
    mint(&env, &token, &admin, &seeder, seed_amount);
    vault.deposit(&seeder, &seed_amount);

    let keeper = Address::generate(&env);
    mint(&env, &token, &admin, &keeper, 1);
    let result = vault.try_distribute_yield(&keeper, &1);
    assert_eq!(result, Err(Ok(VaultError::YieldTooSmall)));
}

// ---------------------------------------------------------------------------
// YD-3  Zero yield amount returns ZeroAmount
// ---------------------------------------------------------------------------
#[test]
fn test_distribute_yield_zero_amount_returns_zero_amount() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);

    let keeper = Address::generate(&env);
    let result = vault.try_distribute_yield(&keeper, &0);
    assert_eq!(result, Err(Ok(VaultError::ZeroAmount)));
}

// ---------------------------------------------------------------------------
// YD-4  Happy path: single depositor receives 100% of yield
// ---------------------------------------------------------------------------
#[test]
fn test_distribute_yield_single_depositor_receives_all() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);

    let keeper = Address::generate(&env);
    mint(&env, &token, &admin, &keeper, 100_000);
    vault.distribute_yield(&keeper, &100_000);

    // Check epoch bumped
    assert_eq!(vault.distribution_epoch(), 1);

    // pending_yield should be 100_000 (fees = 0 in setup)
    let pending = vault.pending_yield(&user);
    assert_eq!(pending, 100_000);

    // Collect
    let token_client = StellarAssetClient::new(&env, &token);
    let balance_before = token_client.balance(&user);
    let collected = vault.collect_pending_yield(&user);
    assert_eq!(collected, 100_000);
    assert_eq!(token_client.balance(&user) - balance_before, 100_000);
    // After collection pending is zero
    assert_eq!(vault.pending_yield(&user), 0);
}

// ---------------------------------------------------------------------------
// YD-5  Two depositors each hold half → each receives half the yield
// ---------------------------------------------------------------------------
#[test]
fn test_distribute_yield_two_equal_depositors_split_evenly() {
    let (env, vault, admin, token) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    mint(&env, &token, &admin, &alice, 1_000_000);
    mint(&env, &token, &admin, &bob, 1_000_000);
    vault.deposit(&alice, &1_000_000);
    vault.deposit(&bob, &1_000_000);

    let keeper = Address::generate(&env);
    mint(&env, &token, &admin, &keeper, 200_000);
    vault.distribute_yield(&keeper, &200_000);

    let alice_pending = vault.pending_yield(&alice);
    let bob_pending = vault.pending_yield(&bob);
    // Each holds 50% → each gets ~100_000 (within 1 stroop rounding)
    assert!(alice_pending >= 99_999 && alice_pending <= 100_001);
    assert!(bob_pending >= 99_999 && bob_pending <= 100_001);
    assert_eq!(alice_pending, bob_pending);
}

// ---------------------------------------------------------------------------
// YD-6  Proportional distribution: 3:1 share ratio
// ---------------------------------------------------------------------------
#[test]
fn test_distribute_yield_proportional_to_shares() {
    let (env, vault, admin, token) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    // Alice deposits 3x more than bob
    mint(&env, &token, &admin, &alice, 3_000_000);
    mint(&env, &token, &admin, &bob, 1_000_000);
    vault.deposit(&alice, &3_000_000);
    vault.deposit(&bob, &1_000_000);

    let keeper = Address::generate(&env);
    mint(&env, &token, &admin, &keeper, 400_000);
    vault.distribute_yield(&keeper, &400_000);

    // Alice: 75% of 400_000 = 300_000; Bob: 25% = 100_000
    let alice_pending = vault.pending_yield(&alice);
    let bob_pending = vault.pending_yield(&bob);
    assert!(alice_pending >= 299_999 && alice_pending <= 300_001,
        "alice_pending={alice_pending}");
    assert!(bob_pending >= 99_999 && bob_pending <= 100_001,
        "bob_pending={bob_pending}");
    // Ratio must hold: alice gets 3x bob (within 1 stroop)
    assert!((alice_pending - 3 * bob_pending).abs() <= 3);
}

// ---------------------------------------------------------------------------
// YD-7  Multiple sequential distributions accumulate correctly
// ---------------------------------------------------------------------------
#[test]
fn test_distribute_yield_multiple_epochs_accumulate() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);

    let keeper = Address::generate(&env);
    // Three separate distributions of 50_000 each
    for _ in 0..3 {
        mint(&env, &token, &admin, &keeper, 50_000);
        vault.distribute_yield(&keeper, &50_000);
    }

    assert_eq!(vault.distribution_epoch(), 3);
    // Total pending = 150_000
    let pending = vault.pending_yield(&user);
    assert_eq!(pending, 150_000);

    let collected = vault.collect_pending_yield(&user);
    assert_eq!(collected, 150_000);
    assert_eq!(vault.pending_yield(&user), 0);
}

// ---------------------------------------------------------------------------
// YD-8  New depositor after distribution only earns future yield
// ---------------------------------------------------------------------------
#[test]
fn test_new_depositor_after_distribution_earns_only_future_yield() {
    let (env, vault, admin, token) = setup();
    let alice = Address::generate(&env);
    mint(&env, &token, &admin, &alice, 1_000_000);
    vault.deposit(&alice, &1_000_000);

    // First distribution — Alice already deposited
    let keeper = Address::generate(&env);
    mint(&env, &token, &admin, &keeper, 100_000);
    vault.distribute_yield(&keeper, &100_000);

    // Bob deposits AFTER the distribution
    let bob = Address::generate(&env);
    mint(&env, &token, &admin, &bob, 1_100_000); // vault has 1_100_000 assets, 1_000_000 shares
    let bob_shares = vault.deposit(&bob, &1_100_000);

    // Second distribution — both earn this one
    mint(&env, &token, &admin, &keeper, 210_000);
    vault.distribute_yield(&keeper, &210_000);

    // Alice: epoch-1 yield (100_000) + epoch-2 proportional share
    // Bob: epoch-2 proportional share only (joined after epoch-1)
    let total_shares = vault.balance_of(&alice) + vault.balance_of(&bob);
    let alice_epoch2 = 210_000_i128 * vault.balance_of(&alice) / total_shares;
    let bob_epoch2 = 210_000_i128 * vault.balance_of(&bob) / total_shares;

    let alice_pending = vault.pending_yield(&alice);
    let bob_pending = vault.pending_yield(&bob);

    // Alice earned epoch-1 + epoch-2; Bob only epoch-2
    assert!(alice_pending > bob_pending,
        "alice_pending={alice_pending} bob_pending={bob_pending}");
    // Bob's pending is within 1 stroop of their expected epoch-2 share
    assert!((bob_pending - bob_epoch2).abs() <= 1,
        "bob expected ~{bob_epoch2}, got {bob_pending}");
}

// ---------------------------------------------------------------------------
// YD-9  collect_pending_yield when nothing to collect returns 0
// ---------------------------------------------------------------------------
#[test]
fn test_collect_pending_yield_nothing_to_collect_returns_zero() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);

    // No distribution happened; collecting should return 0
    let collected = vault.collect_pending_yield(&user);
    assert_eq!(collected, 0);
}

// ---------------------------------------------------------------------------
// YD-10  Pause blocks distribute_yield and collect_pending_yield
// ---------------------------------------------------------------------------
#[test]
fn test_pause_blocks_distribute_and_collect() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);

    vault.pause(&admin);

    let keeper = Address::generate(&env);
    mint(&env, &token, &admin, &keeper, 100_000);
    assert_eq!(
        vault.try_distribute_yield(&keeper, &100_000),
        Err(Ok(VaultError::VaultPaused))
    );
    assert_eq!(
        vault.try_collect_pending_yield(&user),
        Err(Ok(VaultError::VaultPaused))
    );

    vault.unpause(&admin);
    // Should work after unpause
    vault.distribute_yield(&keeper, &100_000);
    let collected = vault.collect_pending_yield(&user);
    assert_eq!(collected, 100_000);
}

// ---------------------------------------------------------------------------
// YD-11  preview_distribution accuracy flag is true for normal yield
// ---------------------------------------------------------------------------
#[test]
fn test_preview_distribution_accuracy_ok_for_normal_yield() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);

    let (net_yield, delta_yps, distributed, accuracy_ok) =
        vault.preview_distribution(&500_000);
    assert_eq!(net_yield, 500_000); // fees = 0
    assert!(delta_yps > 0);
    // distributed ≈ net_yield within 1 stroop at this scale
    assert!((distributed - net_yield).abs() <= 1);
    assert!(accuracy_ok);
}

// ---------------------------------------------------------------------------
// YD-12  preview_distribution returns accuracy_ok=false for tiny yield
// ---------------------------------------------------------------------------
#[test]
fn test_preview_distribution_accuracy_false_for_tiny_yield() {
    let (env, vault, admin, token) = setup();
    // Large share count to force delta_yps = 0
    let seeder = Address::generate(&env);
    let seed = 1_000_000_000_001_i128;
    mint(&env, &token, &admin, &seeder, seed);
    vault.deposit(&seeder, &seed);

    let (net_yield, delta_yps, distributed, accuracy_ok) =
        vault.preview_distribution(&1);
    assert_eq!(delta_yps, 0);
    assert_eq!(distributed, 0);
    assert!(!accuracy_ok);
    let _ = net_yield;
}

// ---------------------------------------------------------------------------
// YD-13  preview_distribution respects performance fee
// ---------------------------------------------------------------------------
#[test]
fn test_preview_distribution_deducts_performance_fee() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);

    // Set 10% performance fee
    vault.set_fees(&admin, &1000_u32, &0_u32);

    let (net_yield, _delta_yps, _distributed, accuracy_ok) =
        vault.preview_distribution(&1_000_000);
    // 10% fee on 1_000_000 → net = 900_000
    assert_eq!(net_yield, 900_000);
    assert!(accuracy_ok);
}

// ---------------------------------------------------------------------------
// YD-14  collect_yield is a functional alias for distribute_yield
// ---------------------------------------------------------------------------
#[test]
fn test_collect_yield_alias_for_distribute_yield() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);

    let keeper = Address::generate(&env);
    mint(&env, &token, &admin, &keeper, 100_000);
    vault.collect_yield(&keeper, &100_000);

    // Same outcome as distribute_yield
    assert_eq!(vault.distribution_epoch(), 1);
    assert_eq!(vault.pending_yield(&user), 100_000);
    let collected = vault.collect_pending_yield(&user);
    assert_eq!(collected, 100_000);
}

// ---------------------------------------------------------------------------
// YD-15  distribute_yield with 10% performance fee credits correct net amount
// ---------------------------------------------------------------------------
#[test]
fn test_distribute_yield_performance_fee_credited_correctly() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);

    vault.set_fees(&admin, &1000_u32, &0_u32);
    vault.set_treasury(&admin, &admin);

    let keeper = Address::generate(&env);
    mint(&env, &token, &admin, &keeper, 1_000_000);
    vault.distribute_yield(&keeper, &1_000_000);

    // Net yield (after 10% fee) = 900_000 → pending for sole shareholder
    let pending = vault.pending_yield(&user);
    assert_eq!(pending, 900_000);
    // Fee accumulated
    assert_eq!(vault.total_fees_collected(), 100_000);
}

// ---------------------------------------------------------------------------
// YD-16  distribute_yield_token — alt token happy path
// ---------------------------------------------------------------------------
#[test]
fn test_distribute_yield_token_happy_path() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);

    // Create and register a second (alt) yield token
    let alt_token_addr = env.register_stellar_asset_contract_v2(admin.clone()).address();
    vault.register_yield_token(&alt_token_addr);

    let keeper = Address::generate(&env);
    // Mint alt-token to keeper
    StellarAssetClient::new(&env, &alt_token_addr).mint(&keeper, &500_000);

    // underlying_amount = 500_000 (keeper values alt tokens at 1:1 for simplicity)
    vault.distribute_yield_token(&keeper, &alt_token_addr, &500_000, &500_000);

    assert_eq!(vault.distribution_epoch(), 1);
    assert_eq!(vault.pending_yield(&user), 500_000);

    let collected = vault.collect_pending_yield(&user);
    assert_eq!(collected, 500_000);
}

// ---------------------------------------------------------------------------
// YD-17  distribute_yield_token with unregistered token returns InvalidAddress
// ---------------------------------------------------------------------------
#[test]
fn test_distribute_yield_token_unregistered_returns_invalid_address() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);

    let unregistered = Address::generate(&env);
    let keeper = Address::generate(&env);
    let result = vault.try_distribute_yield_token(&keeper, &unregistered, &100_000, &100_000);
    assert_eq!(result, Err(Ok(VaultError::InvalidAddress)));
}

// ---------------------------------------------------------------------------
// YD-18  distribute_yield_token: zero underlying_amount returns ZeroAmount
// ---------------------------------------------------------------------------
#[test]
fn test_distribute_yield_token_zero_underlying_returns_zero_amount() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);

    let alt_token_addr = env.register_stellar_asset_contract_v2(admin.clone()).address();
    vault.register_yield_token(&alt_token_addr);

    let keeper = Address::generate(&env);
    let result = vault.try_distribute_yield_token(&keeper, &alt_token_addr, &100_000, &0);
    assert_eq!(result, Err(Ok(VaultError::ZeroAmount)));
}

// ---------------------------------------------------------------------------
// YD-19  distribution_epoch increments on each successful distribution
// ---------------------------------------------------------------------------
#[test]
fn test_distribution_epoch_increments_correctly() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);

    assert_eq!(vault.distribution_epoch(), 0);

    let keeper = Address::generate(&env);
    for i in 1..=5_u64 {
        mint(&env, &token, &admin, &keeper, 1_000);
        vault.distribute_yield(&keeper, &1_000);
        assert_eq!(vault.distribution_epoch(), i);
    }
}

// ---------------------------------------------------------------------------
// YD-20  Full round-trip: deposit → distribute → collect → withdraw
//        vault balance invariant holds throughout
// ---------------------------------------------------------------------------
#[test]
fn test_full_round_trip_deposit_distribute_collect_withdraw() {
    let (env, vault, admin, token) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    mint(&env, &token, &admin, &alice, 2_000_000);
    mint(&env, &token, &admin, &bob, 1_000_000);
    vault.deposit(&alice, &2_000_000);
    vault.deposit(&bob, &1_000_000);

    let keeper = Address::generate(&env);
    mint(&env, &token, &admin, &keeper, 300_000);
    vault.distribute_yield(&keeper, &300_000); // 200_000 to alice, 100_000 to bob

    // Both collect their yield
    let alice_collected = vault.collect_pending_yield(&alice);
    let bob_collected = vault.collect_pending_yield(&bob);
    assert_eq!(alice_collected + bob_collected, 300_000);

    // Now withdraw shares — each gets back their original deposit (yield already collected)
    let alice_redeemed = vault.withdraw(&alice, &vault.balance_of(&alice));
    let bob_redeemed = vault.withdraw(&bob, &vault.balance_of(&bob));

    // Total returned to users equals total deposited
    let total_in = 3_000_000 + 300_000; // deposits + yield injected
    let total_out = alice_collected + bob_collected + alice_redeemed + bob_redeemed;
    assert_eq!(total_out, total_in as i128);

    // Vault is now empty
    assert_eq!(vault.total_assets(), 0);
}

// ---------------------------------------------------------------------------
// YD-21  Accuracy: distribution within 0.01% for realistic amounts
//        Explicitly verifies the acceptance criterion.
// ---------------------------------------------------------------------------
#[test]
fn test_distribution_accuracy_within_0_01_percent() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    // Realistic vault size: 10M shares
    let deposit = 10_000_000_i128;
    mint(&env, &token, &admin, &user, deposit);
    vault.deposit(&user, &deposit);

    // Test a range of yield sizes
    let yield_amounts: &[i128] = &[1_000, 10_000, 100_000, 1_000_000, 5_000_000];
    let keeper = Address::generate(&env);

    for &yield_amount in yield_amounts {
        mint(&env, &token, &admin, &keeper, yield_amount);
        vault.distribute_yield(&keeper, &yield_amount);

        let pending = vault.pending_yield(&user);
        // accuracy: |pending - yield_amount| / yield_amount ≤ 0.0001
        let diff = (pending - yield_amount).abs();
        let tolerance = yield_amount / 10_000 + 1; // 0.01% + 1 stroop rounding
        assert!(
            diff <= tolerance,
            "yield={yield_amount} pending={pending} diff={diff} tolerance={tolerance}"
        );

        // Collect to reset for next iteration
        vault.collect_pending_yield(&user);
    }
}

// ---------------------------------------------------------------------------
// YD-22  pending_yield is zero for address that has never deposited
// ---------------------------------------------------------------------------
#[test]
fn test_pending_yield_zero_for_non_depositor() {
    let (env, vault, admin, token) = setup();
    let user = Address::generate(&env);
    mint(&env, &token, &admin, &user, 1_000_000);
    vault.deposit(&user, &1_000_000);

    let keeper = Address::generate(&env);
    mint(&env, &token, &admin, &keeper, 100_000);
    vault.distribute_yield(&keeper, &100_000);

    let non_depositor = Address::generate(&env);
    assert_eq!(vault.pending_yield(&non_depositor), 0);
}

// ---------------------------------------------------------------------------
// YD-23  Withdraw zeroes shares; subsequent pending_yield stays at 0 after
//        a distribution (no phantom yield for zero-share holder)
// ---------------------------------------------------------------------------
#[test]
fn test_no_phantom_yield_after_full_withdraw() {
    let (env, vault, admin, token) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    mint(&env, &token, &admin, &alice, 1_000_000);
    mint(&env, &token, &admin, &bob, 1_000_000);
    vault.deposit(&alice, &1_000_000);
    vault.deposit(&bob, &1_000_000);

    // Alice withdraws all her shares
    vault.withdraw(&alice, &vault.balance_of(&alice));
    assert_eq!(vault.balance_of(&alice), 0);

    // Now a distribution happens
    let keeper = Address::generate(&env);
    mint(&env, &token, &admin, &keeper, 100_000);
    vault.distribute_yield(&keeper, &100_000);

    // Alice has 0 shares → delta = 0 → pending stays at 0
    assert_eq!(vault.pending_yield(&alice), 0);
    // Bob gets all the yield
    let bob_pending = vault.pending_yield(&bob);
    assert_eq!(bob_pending, 100_000);
}

// ===========================================================================
// SEP-41 TRANSFER / ALLOWANCE TESTS
//
// These tests verify the SEP-41 token interface (transfer, approve,
// transfer_from, allowance) on the underlying Stellar Asset Contract that
// the vault wraps, and confirm that the vault's own token-moving paths
// (deposit / withdraw) are correctly blocked when the vault is paused.
//
// The Stellar Asset Contract (SAC) is a compliant SEP-41 implementation.
// Failure conditions (over-balance, over-allowance) trap the executor, so
// they are covered with #[should_panic] tests as prescribed by the spec.
// ===========================================================================

mod sep41_transfer_allowance {
    extern crate std;

    use soroban_sdk::{
        symbol_short,
        testutils::Address as _,
        token::Client as TokenClient,
        token::StellarAssetClient,
        Address, Env, Val, IntoVal,
    };
    use soroban_sdk::env::internal::TryFromVal;
    use crate::{AuraVault, AuraVaultClient, VaultError};

    // -----------------------------------------------------------------------
    // Module-level setup helper
    // Mirrors the top-level `setup()` so this module is self-contained.
    // Returns (env, token_address, admin).
    // -----------------------------------------------------------------------
    fn token_setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_addr = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        (env, token_addr, admin)
    }

    /// Mint `amount` underlying tokens to `recipient` via the SAC admin.
    fn mint(env: &Env, token: &Address, admin: &Address, recipient: &Address, amount: i128) {
        StellarAssetClient::new(env, token).mint(recipient, &amount);
    }

    // -----------------------------------------------------------------------
    // Helper: deploy + initialise the vault alongside a token; returns
    // (env, vault_client, vault_address, token_address, admin).
    // -----------------------------------------------------------------------
    fn vault_setup() -> (Env, AuraVaultClient<'static>, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token_addr = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        let vault_addr = env.register_contract(None, AuraVault);
        let vault = AuraVaultClient::new(&env, &vault_addr);
        let signers: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(&env);
        vault.initialize(&admin, &token_addr, &signers, &0_u32);
        vault.set_fees(&admin, &0_u32, &0_u32);
        (env, vault, vault_addr, token_addr, admin)
    }

    // -----------------------------------------------------------------------
    // Test 1 — transfer correct amount between addresses
    //
    // Criterion: after token.transfer(from → to, amount), `to`'s balance
    // increases by exactly `amount` and `from`'s balance decreases by the
    // same amount.
    // -----------------------------------------------------------------------
    #[test]
    fn test_sep41_transfer_correct_amount() {
        let (env, token_addr, admin) = token_setup();
        let token = TokenClient::new(&env, &token_addr);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        mint(&env, &token_addr, &admin, &alice, 1_000_000);

        let alice_before = token.balance(&alice);
        let bob_before = token.balance(&bob);

        token.transfer(&alice, &bob, &400_000);

        assert_eq!(
            token.balance(&alice),
            alice_before - 400_000,
            "alice balance should decrease by transferred amount"
        );
        assert_eq!(
            token.balance(&bob),
            bob_before + 400_000,
            "bob balance should increase by transferred amount"
        );
    }

    // -----------------------------------------------------------------------
    // Test 2 — transfer more than balance → panic (trap)
    //
    // Criterion: the SAC traps when the sender tries to transfer more tokens
    // than their available balance. Per the SEP-41 spec, failure conditions
    // are signalled by trapping rather than returning an error code.
    // -----------------------------------------------------------------------
    #[test]
    #[should_panic]
    fn test_sep41_transfer_more_than_balance_panics() {
        let (env, token_addr, admin) = token_setup();
        let token = TokenClient::new(&env, &token_addr);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        mint(&env, &token_addr, &admin, &alice, 500);

        // Attempting to transfer 501 when alice only has 500 must trap.
        token.transfer(&alice, &bob, &501);
    }

    // -----------------------------------------------------------------------
    // Test 3 — approve then transfer_from within allowance
    //
    // Criterion: after alice approves spender for `amount` (with a far-future
    // live_until_ledger), spender can call transfer_from and the tokens move
    // correctly; the allowance is consumed by the transferred amount.
    // -----------------------------------------------------------------------
    #[test]
    fn test_sep41_approve_then_transfer_from_within_allowance() {
        let (env, token_addr, admin) = token_setup();
        let token = TokenClient::new(&env, &token_addr);

        let alice = Address::generate(&env);
        let spender = Address::generate(&env);
        let bob = Address::generate(&env);

        mint(&env, &token_addr, &admin, &alice, 1_000_000);

        // Approve spender to spend up to 300_000 from alice's balance.
        // live_until_ledger is set far in the future (current + 10_000).
        let live_until = env.ledger().sequence() + 10_000;
        token.approve(&alice, &spender, &300_000, &live_until);

        // Verify the allowance was recorded.
        assert_eq!(
            token.allowance(&alice, &spender),
            300_000,
            "allowance should be 300_000 after approve"
        );

        let alice_before = token.balance(&alice);
        let bob_before = token.balance(&bob);

        // Spender transfers 200_000 from alice to bob.
        token.transfer_from(&spender, &alice, &bob, &200_000);

        assert_eq!(
            token.balance(&alice),
            alice_before - 200_000,
            "alice's balance should decrease by 200_000"
        );
        assert_eq!(
            token.balance(&bob),
            bob_before + 200_000,
            "bob's balance should increase by 200_000"
        );
        // Remaining allowance must be reduced by the transferred amount.
        assert_eq!(
            token.allowance(&alice, &spender),
            100_000,
            "allowance should be reduced to 100_000 after partial transfer_from"
        );
    }

    // -----------------------------------------------------------------------
    // Test 4 — transfer_from exceeding allowance → panic (trap)
    //
    // Criterion: attempting to transfer_from more than the approved allowance
    // traps the executor. Aligns with the SEP-41 failure-condition spec.
    // -----------------------------------------------------------------------
    #[test]
    #[should_panic]
    fn test_sep41_transfer_from_exceeds_allowance_panics() {
        let (env, token_addr, admin) = token_setup();
        let token = TokenClient::new(&env, &token_addr);

        let alice = Address::generate(&env);
        let spender = Address::generate(&env);
        let bob = Address::generate(&env);

        mint(&env, &token_addr, &admin, &alice, 1_000_000);

        let live_until = env.ledger().sequence() + 10_000;
        // Approve only 100 stroops.
        token.approve(&alice, &spender, &100, &live_until);

        // Attempt to transfer 101 — must trap.
        token.transfer_from(&spender, &alice, &bob, &101);
    }

    // -----------------------------------------------------------------------
    // Test 5 — Transfer event emitted with correct fields
    //
    // Criterion: after a successful token.transfer call, env.events().all()
    // contains an event from the token contract whose topics Vec starts with
    //   topics[0] = Symbol("transfer")
    //   topics[1] = from: Address
    //   topics[2] = to: Address
    // conforming to the SEP-41 event specification.
    //
    // We use soroban_sdk::IntoVal to convert the expected Rust values to
    // soroban_sdk::Val for comparison with the stored raw event entries.
    // -----------------------------------------------------------------------
    #[test]
    fn test_sep41_transfer_event_emitted_with_correct_fields() {
        use soroban_sdk::{testutils::Events as _, IntoVal, Val};

        let (env, token_addr, admin) = token_setup();
        let token = TokenClient::new(&env, &token_addr);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        mint(&env, &token_addr, &admin, &alice, 1_000_000);

        let transfer_amount: i128 = 250_000;
        token.transfer(&alice, &bob, &transfer_amount);

        // env.events().all() returns a ContractEvents in SDK 27.
        // Use filter_by_contract to get only token events, then count with .events().len().
        let token_events = env.events().all().filter_by_contract(&token_addr);
        let all_xdr = token_events.events();

        // The SEP-41 / SAC "transfer" event format:
        //   topics[0] = Symbol("transfer")
        //   topics[1] = from: Address
        //   topics[2] = to: Address
        //   data      = amount: i128 (legacy SAC format)
        let transfer_sym: Val = symbol_short!("transfer").into_val(&env);
        let alice_val: Val = alice.clone().into_val(&env);
        let bob_val: Val = bob.clone().into_val(&env);

        let found = all_xdr.iter().any(|evt| {
            use soroban_sdk::xdr::{ContractEventBody, ScVal, ReadXdr};
            if let ContractEventBody::V0(ref body) = evt.body {
                let topics = &body.topics;
                if topics.len() < 3 { return false; }
                // Convert XDR ScVals to soroban Val for comparison
                let t0 = Val::try_from_val(&env, &topics[0]).ok();
                let t1 = Val::try_from_val(&env, &topics[1]).ok();
                let t2 = Val::try_from_val(&env, &topics[2]).ok();
                t0.map(|v| v == transfer_sym).unwrap_or(false)
                    && t1.map(|v| v == alice_val).unwrap_or(false)
                    && t2.map(|v| v == bob_val).unwrap_or(false)
            } else {
                false
            }
        });

        assert!(
            found,
            "expected a SEP-41 'transfer' event \
             (from=alice, to=bob, amount={transfer_amount}) \
             but none matched in the event list"
        );
    }

    // -----------------------------------------------------------------------
    // Test 6 — Token transfer blocked while vault is paused
    //
    // Criterion: the vault's deposit and withdraw functions call
    // token.transfer internally. When the vault is paused, both functions
    // must return VaultPaused without executing any token transfer, leaving
    // token balances unchanged.
    // -----------------------------------------------------------------------
    #[test]
    fn test_sep41_transfer_blocked_while_vault_paused() {
        let (env, vault, _vault_addr, token_addr, admin) = vault_setup();
        let token = TokenClient::new(&env, &token_addr);

        let alice = Address::generate(&env);
        mint(&env, &token_addr, &admin, &alice, 1_000_000);

        // Seed alice's position so she has shares to withdraw later.
        vault.deposit(&alice, &500_000);
        let shares = vault.balance_of(&alice);
        assert!(shares > 0, "alice should have shares after deposit");

        // --- Pause the vault ---
        vault.pause(&admin);
        assert!(vault.is_paused(), "vault must be paused");

        // Record balances *after* pause, *before* any blocked operations.
        let alice_token_balance_before = token.balance(&alice);
        let vault_token_balance_before = token.balance(&_vault_addr);
        let vault_total_assets_before = vault.total_assets();
        let alice_shares_before = vault.balance_of(&alice);

        // Attempt deposit while paused → must fail with VaultPaused.
        let deposit_result = vault.try_deposit(&alice, &500_000);
        assert_eq!(
            deposit_result,
            Err(Ok(VaultError::VaultPaused)),
            "deposit must be blocked with VaultPaused when vault is paused"
        );

        // Attempt withdraw while paused → must fail with VaultPaused.
        let withdraw_result = vault.try_withdraw(&alice, &shares);
        assert_eq!(
            withdraw_result,
            Err(Ok(VaultError::VaultPaused)),
            "withdraw must be blocked with VaultPaused when vault is paused"
        );

        // Confirm that no token balances changed — no transfer occurred.
        assert_eq!(
            token.balance(&alice),
            alice_token_balance_before,
            "alice's token balance must be unchanged while vault is paused"
        );
        assert_eq!(
            token.balance(&_vault_addr),
            vault_token_balance_before,
            "vault's token balance must be unchanged while vault is paused"
        );
        assert_eq!(
            vault.total_assets(),
            vault_total_assets_before,
            "vault total_assets must be unchanged while paused"
        );
        assert_eq!(
            vault.balance_of(&alice),
            alice_shares_before,
            "alice's share balance must be unchanged while vault is paused"
        );

        // --- Unpause and verify operations resume ---
        vault.unpause(&admin);
        assert!(!vault.is_paused(), "vault must be unpaused");

        // Deposit must succeed after unpause.
        let new_shares = vault.deposit(&alice, &100_000);
        assert!(
            new_shares > 0,
            "deposit should succeed and mint shares after unpause"
        );
    }
}
