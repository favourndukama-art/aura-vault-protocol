use soroban_sdk::{contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    UnderlyingToken,
    TotalShares,
    TotalDeposited,
    Balance(Address),
    Version,
    LayoutVersion,
    /// Emergency pause flag — when true, deposit/withdraw/harvest are blocked.
    Paused,
    Treasury,
    PerfFeeBps,
    MgmtFeeBps,
    TotalFeeCollected,
    LastMgmtFeeTime,
    /// Whitelisted alternative yield tokens (Issue #48)
    YieldToken(Address),
    /// Maximum total assets allowed (0 = unlimited). Issue #467.
    TvlCap,
    /// Timestamp of the last successful harvest (ledger timestamp). Issue #471.
    LastHarvestTime,
    /// Minimum seconds between harvests (0 = no cooldown). Issue #471.
    HarvestCooldownSecs,
    // -----------------------------------------------------------------------
    // Yield-distribution per-share accumulator (Issue #YD)
    // -----------------------------------------------------------------------
    /// Global cumulative yield-per-share (YPS) accumulator (scaled by YIELD_PRECISION).
    CumulativeYps,
    /// Per-user YPS checkpoint: the value of CumulativeYps at the user's last
    /// collect_pending_yield or deposit call.
    UserCheckpoint(Address),
    /// Stored (unsettled) pending yield tokens for a user, in underlying units.
    UserPendingYield(Address),
    /// Monotonically increasing epoch counter; bumped on every distribution.
    DistributionEpoch,
    // -----------------------------------------------------------------------
    // Withdrawal queue (Issue #WQ)
    // -----------------------------------------------------------------------
    /// Minimum underlying-token amount that triggers queue instead of instant withdrawal.
    WithdrawalQueueThreshold,
    /// Minimum seconds a queued withdrawal must wait before it can be claimed.
    WithdrawalUnbondingSecs,
    /// Per-user withdrawal fee in basis points (0 = no fee, max 500 = 5%).
    WithdrawalFeeBps,
    /// Next sequential withdrawal queue ID.
    WithdrawalNextId,
    /// Individual withdrawal queue entry keyed by queue ID.
    WithdrawalEntry(u64),
    /// Share price precision multiplier (default: 10_000_000 = 10^7 for Stellar's
    /// 7-decimal standard). Stored as u32; used in share price view calculations.
    /// Does NOT affect deposit/withdraw share arithmetic — that always uses the
    /// raw token unit ratio to prevent rounding attacks.  The precision value is
    /// used exclusively by `share_price()` to return a human-readable fixed-point
    /// representation of the exchange rate.
    PricePrecision,
}

pub const DAY_IN_LEDGERS: u32 = 17_280;
pub const INSTANCE_LIFETIME_THRESHOLD: u32 = DAY_IN_LEDGERS * 7;
pub const INSTANCE_BUMP_AMOUNT: u32 = DAY_IN_LEDGERS * 30;
pub const PERSISTENT_LIFETIME_THRESHOLD: u32 = DAY_IN_LEDGERS * 7;
pub const PERSISTENT_BUMP_AMOUNT: u32 = DAY_IN_LEDGERS * 30;

// ---------------------------------------------------------------------------
// Instance-storage helpers
// ---------------------------------------------------------------------------

pub fn get_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::Admin)
}

pub fn set_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&DataKey::Admin, admin);
}

pub fn get_token(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::UnderlyingToken)
}

pub fn set_token(env: &Env, token: &Address) {
    env.storage().instance().set(&DataKey::UnderlyingToken, token);
}

pub fn get_total_shares(env: &Env) -> i128 {
    env.storage().instance().get(&DataKey::TotalShares).unwrap_or(0)
}

pub fn set_total_shares(env: &Env, val: i128) {
    env.storage().instance().set(&DataKey::TotalShares, &val);
}

pub fn get_total_deposited(env: &Env) -> i128 {
    env.storage().instance().get(&DataKey::TotalDeposited).unwrap_or(0)
}

pub fn set_total_deposited(env: &Env, val: i128) {
    env.storage().instance().set(&DataKey::TotalDeposited, &val);
}

// ---------------------------------------------------------------------------
// Persistent-storage helpers
// ---------------------------------------------------------------------------

pub fn get_balance(env: &Env, addr: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(addr.clone()))
        .unwrap_or(0)
}

pub fn set_balance(env: &Env, addr: &Address, val: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(addr.clone()), &val);
}

// ---------------------------------------------------------------------------
// Fee storage helpers (instance storage)
// ---------------------------------------------------------------------------

pub fn get_treasury(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::Treasury)
}

pub fn set_treasury(env: &Env, treasury: &Address) {
    env.storage().instance().set(&DataKey::Treasury, treasury);
}

pub fn get_perf_fee_bps(env: &Env) -> u32 {
    env.storage().instance().get(&DataKey::PerfFeeBps).unwrap_or(1000)
}

pub fn set_perf_fee_bps(env: &Env, bps: u32) {
    env.storage().instance().set(&DataKey::PerfFeeBps, &bps);
}

pub fn get_mgmt_fee_bps(env: &Env) -> u32 {
    env.storage().instance().get(&DataKey::MgmtFeeBps).unwrap_or(0)
}

pub fn set_mgmt_fee_bps(env: &Env, bps: u32) {
    env.storage().instance().set(&DataKey::MgmtFeeBps, &bps);
}

pub fn get_total_fee_collected(env: &Env) -> i128 {
    env.storage().instance().get(&DataKey::TotalFeeCollected).unwrap_or(0)
}

pub fn set_total_fee_collected(env: &Env, val: i128) {
    env.storage().instance().set(&DataKey::TotalFeeCollected, &val);
}

pub fn get_last_mgmt_fee_time(env: &Env) -> u64 {
    env.storage().instance().get(&DataKey::LastMgmtFeeTime).unwrap_or(0)
}

pub fn set_last_mgmt_fee_time(env: &Env, time: u64) {
    env.storage().instance().set(&DataKey::LastMgmtFeeTime, &time);
}

// ---------------------------------------------------------------------------
// Yield-token whitelist helpers (instance storage — Issue #48)
// ---------------------------------------------------------------------------

pub fn is_yield_token(env: &Env, token: &Address) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::YieldToken(token.clone()))
        .unwrap_or(false)
}

pub fn set_yield_token(env: &Env, token: &Address, enabled: bool) {
    env.storage()
        .instance()
        .set(&DataKey::YieldToken(token.clone()), &enabled);
}

// ---------------------------------------------------------------------------
// TTL bump helpers
// ---------------------------------------------------------------------------

pub fn bump_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
}

pub fn bump_persistent(env: &Env, addr: &Address) {
    env.storage()
        .persistent()
        .extend_ttl(
            &DataKey::Balance(addr.clone()),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
}

// ---------------------------------------------------------------------------
// Version helpers (instance storage — same TTL as the rest of state)
// ---------------------------------------------------------------------------

/// Current storage layout constant. Bump this in source whenever a new
/// DataKey variant changes an existing key's meaning.
pub const CURRENT_LAYOUT_VERSION: u32 = 1;

pub fn get_version(env: &Env) -> u32 {
    env.storage().instance().get(&DataKey::Version).unwrap_or(0)
}

pub fn set_version(env: &Env, v: u32) {
    env.storage().instance().set(&DataKey::Version, &v);
}

pub fn get_layout_version(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::LayoutVersion)
        .unwrap_or(0)
}

pub fn set_layout_version(env: &Env, v: u32) {
    env.storage().instance().set(&DataKey::LayoutVersion, &v);
}

// ---------------------------------------------------------------------------
// Pause helpers (instance storage)
// ---------------------------------------------------------------------------

pub fn is_paused(env: &Env) -> bool {
    env.storage().instance().get(&DataKey::Paused).unwrap_or(false)
}

pub fn set_paused(env: &Env, paused: bool) {
    env.storage().instance().set(&DataKey::Paused, &paused);
}

// ---------------------------------------------------------------------------
// TVL cap helpers (instance storage) — Issue #467
// 0 means unlimited.
// ---------------------------------------------------------------------------

pub fn get_tvl_cap(env: &Env) -> i128 {
    env.storage().instance().get(&DataKey::TvlCap).unwrap_or(0)
}

pub fn set_tvl_cap(env: &Env, cap: i128) {
    env.storage().instance().set(&DataKey::TvlCap, &cap);
}

// ---------------------------------------------------------------------------
// Harvest cooldown helpers (instance storage) — Issue #471
// ---------------------------------------------------------------------------

/// Timestamp (ledger unix seconds) of the last successful harvest. 0 = never.
pub fn get_last_harvest_time(env: &Env) -> u64 {
    env.storage().instance().get(&DataKey::LastHarvestTime).unwrap_or(0)
}

pub fn set_last_harvest_time(env: &Env, ts: u64) {
    env.storage().instance().set(&DataKey::LastHarvestTime, &ts);
}

/// Minimum seconds that must elapse between harvests. 0 = no cooldown.
pub fn get_harvest_cooldown_secs(env: &Env) -> u64 {
    env.storage().instance().get(&DataKey::HarvestCooldownSecs).unwrap_or(0)
}

pub fn set_harvest_cooldown_secs(env: &Env, secs: u64) {
    env.storage().instance().set(&DataKey::HarvestCooldownSecs, &secs);
}

// ---------------------------------------------------------------------------
// Yield-distribution accumulator helpers (Issue #YD)
// ---------------------------------------------------------------------------

/// Global cumulative yield-per-share (YPS), scaled by YIELD_PRECISION.
pub fn get_cumulative_yps(env: &Env) -> i128 {
    env.storage().instance().get(&DataKey::CumulativeYps).unwrap_or(0)
}

pub fn set_cumulative_yps(env: &Env, val: i128) {
    env.storage().instance().set(&DataKey::CumulativeYps, &val);
}

/// Per-user YPS checkpoint (persistent storage — one entry per user address).
pub fn get_user_checkpoint(env: &Env, addr: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::UserCheckpoint(addr.clone()))
        .unwrap_or(0)
}

pub fn set_user_checkpoint(env: &Env, addr: &Address, val: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::UserCheckpoint(addr.clone()), &val);
}

/// Per-user stored pending yield tokens, in underlying units.
pub fn get_user_pending_yield(env: &Env, addr: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::UserPendingYield(addr.clone()))
        .unwrap_or(0)
}

pub fn set_user_pending_yield(env: &Env, addr: &Address, val: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::UserPendingYield(addr.clone()), &val);
}

/// Global distribution epoch counter.
pub fn get_distribution_epoch(env: &Env) -> u64 {
    env.storage().instance().get(&DataKey::DistributionEpoch).unwrap_or(0)
}

pub fn set_distribution_epoch(env: &Env, epoch: u64) {
    env.storage().instance().set(&DataKey::DistributionEpoch, &epoch);
}

/// TTL bump for per-user yield checkpoint and pending entries.
pub fn bump_user_yield_ttl(env: &Env, addr: &Address) {
    // Bump both entries if they exist; silently skip if not yet set.
    let ck = DataKey::UserCheckpoint(addr.clone());
    if env.storage().persistent().has(&ck) {
        env.storage().persistent().extend_ttl(&ck, PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
    }
    let py = DataKey::UserPendingYield(addr.clone());
    if env.storage().persistent().has(&py) {
        env.storage().persistent().extend_ttl(&py, PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
    }
}

// ---------------------------------------------------------------------------
// Withdrawal queue helpers (Issue #WQ)
// ---------------------------------------------------------------------------

/// Minimum underlying-token amount that routes a withdrawal through the queue.
/// 0 means all withdrawals are instant (queue disabled).
pub fn get_withdrawal_queue_threshold(env: &Env) -> i128 {
    env.storage().instance().get(&DataKey::WithdrawalQueueThreshold).unwrap_or(0)
}

pub fn set_withdrawal_queue_threshold(env: &Env, threshold: i128) {
    env.storage().instance().set(&DataKey::WithdrawalQueueThreshold, &threshold);
}

/// Seconds a queued withdrawal must wait before it can be claimed.
/// Default 0 (instant once queued — admin sets unbonding period).
pub fn get_withdrawal_unbonding_secs(env: &Env) -> u64 {
    env.storage().instance().get(&DataKey::WithdrawalUnbondingSecs).unwrap_or(0)
}

pub fn set_withdrawal_unbonding_secs(env: &Env, secs: u64) {
    env.storage().instance().set(&DataKey::WithdrawalUnbondingSecs, &secs);
}

/// Withdrawal fee in basis points (0–500). Applied on claim.
pub fn get_withdrawal_fee_bps(env: &Env) -> u32 {
    env.storage().instance().get(&DataKey::WithdrawalFeeBps).unwrap_or(0)
}

pub fn set_withdrawal_fee_bps(env: &Env, bps: u32) {
    env.storage().instance().set(&DataKey::WithdrawalFeeBps, &bps);
}

/// Monotonically-increasing withdrawal queue ID.  The next entry will use
/// this value, then it is incremented.
pub fn get_withdrawal_next_id(env: &Env) -> u64 {
    env.storage().instance().get(&DataKey::WithdrawalNextId).unwrap_or(1)
}

pub fn set_withdrawal_next_id(env: &Env, id: u64) {
    env.storage().instance().set(&DataKey::WithdrawalNextId, &id);
}

/// Retrieve a withdrawal queue entry.
pub fn get_withdrawal_entry(env: &Env, id: u64) -> Option<WithdrawalEntry> {
    env.storage().persistent().get(&DataKey::WithdrawalEntry(id))
}

/// Store a withdrawal queue entry.
pub fn set_withdrawal_entry(env: &Env, id: u64, entry: &WithdrawalEntry) {
    env.storage()
        .persistent()
        .set(&DataKey::WithdrawalEntry(id), entry);
    let key = DataKey::WithdrawalEntry(id);
    env.storage().persistent().extend_ttl(&key, PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
}

/// Remove a withdrawal queue entry (after claim).
pub fn remove_withdrawal_entry(env: &Env, id: u64) {
    env.storage().persistent().remove(&DataKey::WithdrawalEntry(id));
}

/// A single entry in the withdrawal queue.
#[soroban_sdk::contracttype]
#[derive(Clone, Debug)]
pub struct WithdrawalEntry {
    /// Address that queued the withdrawal.
    pub owner: Address,
    /// Number of vault shares burned when this entry was created.
    pub shares: i128,
    /// Underlying token amount to be redeemed (computed at queue time).
    pub redeem_amount: i128,
    /// Ledger timestamp after which the entry may be claimed.
    pub claimable_after: u64,
    /// Whether this entry has already been claimed.
    pub claimed: bool,
}

// ---------------------------------------------------------------------------
// Share price precision helpers (Issue #383)
//
// `price_precision` is the multiplier used by `share_price()` to express the
// exchange rate as a fixed-point integer.
//
// Default: 10_000_000 (10^7) — matches Stellar's 7-decimal stroop standard so
// that `share_price()` returns the exchange rate in the same unit as the
// underlying token's smallest denominator.
//
// Example: if total_assets = 1_050_000_000 and total_shares = 1_000_000_000,
//   share_price = 1_050_000_000 * 10_000_000 / 1_000_000_000 = 10_500_000
//   i.e. 1.05 expressed with 7 decimal places.
//
// Deployers targeting non-7-decimal tokens can pass a different value to
// `initialize` (e.g. 1_000_000 for a 6-decimal USDC-equivalent).
// ---------------------------------------------------------------------------

/// Default price precision: 10^7, matching Stellar's stroop denomination.
pub const DEFAULT_PRICE_PRECISION: u32 = 10_000_000;

/// Return the configured share price precision multiplier.
/// Defaults to `DEFAULT_PRICE_PRECISION` (10^7) if never set.
pub fn get_price_precision(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::PricePrecision)
        .unwrap_or(DEFAULT_PRICE_PRECISION)
}

/// Persist the share price precision multiplier.
pub fn set_price_precision(env: &Env, precision: u32) {
    env.storage()
        .instance()
        .set(&DataKey::PricePrecision, &precision);
}

// ---------------------------------------------------------------------------
// VaultSnapshot — complete state export for off-chain indexing (Issue #381)
//
// All fields are read from instance storage in O(1) gas (instance entry is
// a single ledger blob, loaded once at invocation start).
//
// ## Field semantics
//
// | Field | DataKey | Description |
// |---|---|---|
// | total_assets | TotalDeposited | Current underlying token balance tracked by vault |
// | total_shares | TotalShares | Total outstanding vault shares |
// | admin | Admin | Privileged admin address |
// | underlying_token | UnderlyingToken | SEP-41 token contract address |
// | is_paused | Paused | Whether vault is currently halted |
// | perf_fee_bps | PerfFeeBps | Performance fee in bps (default 1000 = 10%) |
// | mgmt_fee_bps | MgmtFeeBps | Management fee in bps (currently unused) |
// | total_fee_collected | TotalFeeCollected | Accumulated fees not yet withdrawn |
// | tvl_cap | TvlCap | Maximum total assets allowed (0 = unlimited) |
// | last_harvest | LastHarvestTime | Unix timestamp of last successful harvest |
// | harvest_cooldown_secs | HarvestCooldownSecs | Min seconds between harvests (0 = none) |
// | price_precision | PricePrecision | share_price() multiplier (default 10^7) |
// | cumulative_yps | CumulativeYps | Global yield-per-share accumulator |
// | distribution_epoch | DistributionEpoch | Monotonic distribution counter |
// | withdrawal_queue_threshold | WithdrawalQueueThreshold | Queue trigger threshold |
// | withdrawal_unbonding_secs | WithdrawalUnbondingSecs | Queue unbonding period |
// | withdrawal_fee_bps | WithdrawalFeeBps | Fee charged on queued withdrawal claims |
// | version | Version | Contract version (bumped on upgrade) |
// | layout_version | LayoutVersion | Storage schema version |
// ---------------------------------------------------------------------------

/// Complete snapshot of all vault instance-storage state.
///
/// Returned by [`AuraVault::export_state`] for off-chain indexer bootstrap.
/// All fields are sourced from instance storage in a single O(1) call.
///
/// ## Usage
///
/// ```no_run
/// // Rust integration (Soroban test env):
/// let snapshot = vault_client.export_state();
/// assert_eq!(snapshot.version, 1);
/// println!("Total TVL: {}", snapshot.total_assets);
/// ```
///
/// ## Gas cost
///
/// `export_state()` reads exclusively from the contract's instance storage
/// entry, which is loaded into memory at invocation start.  Subsequent field
/// accesses are in-memory lookups — no additional storage ops.  Gas cost is
/// ~1.2× a single `total_assets()` call due to return-value serialisation.
#[soroban_sdk::contracttype]
#[derive(Clone, Debug)]
pub struct VaultSnapshot {
    // -----------------------------------------------------------------------
    // Core accounting
    // -----------------------------------------------------------------------
    /// Total underlying tokens tracked by the vault (= `total_deposited`).
    /// Equals deposits + harvested yield - withdrawals - fee accruals.
    pub total_assets: i128,

    /// Total outstanding vault shares.
    pub total_shares: i128,

    // -----------------------------------------------------------------------
    // Admin / configuration
    // -----------------------------------------------------------------------
    /// Privileged admin address (pause, fees, upgrade, TVL cap, etc.).
    pub admin: Address,

    /// SEP-41 underlying token contract address.
    pub underlying_token: Address,

    /// `true` if the vault is currently paused (deposit/withdraw/harvest blocked).
    pub is_paused: bool,

    // -----------------------------------------------------------------------
    // Fee configuration
    // -----------------------------------------------------------------------
    /// Performance fee in basis points (default 1000 = 10%).
    pub perf_fee_bps: u32,

    /// Management fee in basis points (reserved, currently 0).
    pub mgmt_fee_bps: u32,

    /// Accumulated performance fees not yet transferred to treasury.
    pub total_fee_collected: i128,

    // -----------------------------------------------------------------------
    // TVL cap
    // -----------------------------------------------------------------------
    /// Maximum total assets allowed (0 = unlimited).
    pub tvl_cap: i128,

    // -----------------------------------------------------------------------
    // Harvest timing
    // -----------------------------------------------------------------------
    /// Unix timestamp (seconds) of the last successful `harvest()` call.
    /// `0` means the vault has never been harvested.
    pub last_harvest: u64,

    /// Minimum seconds required between harvest calls. `0` = no cooldown.
    pub harvest_cooldown_secs: u64,

    // -----------------------------------------------------------------------
    // Share price precision
    // -----------------------------------------------------------------------
    /// Multiplier used by `share_price()` (default 10_000_000 = 10^7).
    pub price_precision: u32,

    // -----------------------------------------------------------------------
    // Yield distribution accumulator
    // -----------------------------------------------------------------------
    /// Global cumulative yield-per-share (YPS), scaled by YIELD_PRECISION.
    pub cumulative_yps: i128,

    /// Monotonic distribution epoch counter (bumped on each distribution).
    pub distribution_epoch: u64,

    // -----------------------------------------------------------------------
    // Withdrawal queue configuration
    // -----------------------------------------------------------------------
    /// Redemption amount at or above which withdrawals are queued. 0 = disabled.
    pub withdrawal_queue_threshold: i128,

    /// Seconds a queued withdrawal must wait before it can be claimed.
    pub withdrawal_unbonding_secs: u64,

    /// Fee charged on queued-withdrawal claims in basis points (0–500).
    pub withdrawal_fee_bps: u32,

    // -----------------------------------------------------------------------
    // Contract version
    // -----------------------------------------------------------------------
    /// Contract version counter (monotonically incremented on each upgrade).
    pub version: u32,

    /// Storage schema version (must match CURRENT_LAYOUT_VERSION on upgrade).
    pub layout_version: u32,
}
