"""
Automated Fix Suggester Module v1.0
Provides automated remediation suggestions for detected vulnerabilities

Based on SUWC (Sui-Unified Weakness Classification) taxonomy:
- 4 categories: AUTH, CONS, TIME, RES
- 13 total defects
- Pattern-based mitigation strategies

Author: PhD Candidate Giatzis Antonios
Date: January 21, 2026
"""

from typing import List, Dict, Optional
from enum import Enum
from dataclasses import dataclass

class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class VulnerabilityCategory(Enum):
    """SUWC vulnerability categories"""
    AUTH = "SUWC-AUTH"     # Authorization Defects
    CONS = "SUWC-CONS"     # Consensus/Concurrency Defects
    TIME = "SUWC-TIME"     # Temporal Correctness Defects
    RES = "SUWC-RES"       # Resource Management Defects

@dataclass
class VulnerabilityDetection:
    """Detected vulnerability instance"""
    defect_id: str
    category: VulnerabilityCategory
    severity: SeverityLevel
    function_name: str
    line_number: Optional[int]
    description: str
    evidence: str

@dataclass
class FixSuggestion:
    """Automated fix suggestion"""
    defect_id: str
    title: str
    recommended_pattern: str
    code_fix: str
    explanation: str
    example_code: str
    references: List[str]

class AutomatedFixSuggester:
    """Generates automated fix suggestions for detected vulnerabilities"""

    def __init__(self):
        self.fix_database = self._initialize_fix_database()

    def _initialize_fix_database(self) -> Dict[str, FixSuggestion]:
        """Initialize database of fixes for all 13 SUWC defects"""
        return {
            # ========== SUWC-AUTH (4 defects) ==========
            "SUWC-AUTH-01": FixSuggestion(
                defect_id="SUWC-AUTH-01",
                title="Missing Signer Check",
                recommended_pattern="AccessControlPattern with CapabilityTechnique",
                code_fix="Add capability-based authentication",
                explanation=(
                    "The function lacks proper signer verification, allowing unauthorized "
                    "access. Implement the Access Control Pattern using a capability object "
                    "that enforces ownership checks at the type level."
                ),
                example_code="""
// ❌ VULNERABLE CODE
public fun withdraw(pool: &mut Pool, amount: u64) {
    // Missing authentication - anyone can call this!
    pool.balance = pool.balance - amount;
}

// ✅ FIXED CODE with Access Control Pattern
public struct AdminCap has key { id: UID }  // No 'store' - prevents leakage (see AUTH-02)

public fun withdraw(
    _cap: &AdminCap,  // Capability proves authorization
    pool: &mut Pool, 
    amount: u64
) {
    // Only caller with AdminCap can execute
    pool.balance = pool.balance - amount;
}
""",
                references=[
                    "Sui Framework: sui::transfer_policy",
                    "Pattern: AccessControlPattern",
                    "Ontology: sui:implementsPattern -> CapabilityTechnique"
                ]
            ),

            "SUWC-AUTH-02": FixSuggestion(
                defect_id="SUWC-AUTH-02",
                title="Capability Leakage",
                recommended_pattern="AccessControlPattern with Singleton Enforcement",
                code_fix="Remove store/copy abilities from capability structs",
                explanation=(
                    "AdminCap with store/copy ability can be duplicated and leaked to "
                    "unauthorized users. Remove these abilities and ensure capabilities "
                    "are created only once using the One-Time Witness (OTW) pattern."
                ),
                example_code="""
// ❌ VULNERABLE CODE
public struct AdminCap has key, store, copy {  // DANGER: copy + store
    id: UID
}

// ✅ FIXED CODE
public struct AdminCap has key {  // Only 'key' - cannot be copied/stored
    id: UID
}

// Create exactly one capability using OTW
fun init(otw: PROTOCOL_OTW, ctx: &mut TxContext) {
    let admin_cap = AdminCap { id: object::new(ctx) };
    transfer::transfer(admin_cap, tx_context::sender(ctx));
}
""",
                references=[
                    "Sui Framework: sui::coin::TreasuryCap",
                    "Pattern: Witness Pattern",
                    "SUWC: Prevents privilege escalation"
                ]
            ),

            "SUWC-AUTH-03": FixSuggestion(
                defect_id="SUWC-AUTH-03",
                title="Witness Pattern Violation",
                recommended_pattern="One-Time Witness (OTW) Pattern",
                code_fix="Consume OTW by value, not by reference",
                explanation=(
                    "The One-Time Witness struct is borrowed (&OTW) instead of consumed by "
                    "value, allowing it to be reused multiple times. OTW must be moved (consumed) "
                    "to guarantee single execution."
                ),
                example_code="""
// ❌ VULNERABLE CODE
public fun init_pool(
    witness: &PROTOCOL_OTW,  // DANGER: borrowed, can be reused!
    ctx: &mut TxContext
) {
    // Malicious caller can call this multiple times
}

// ✅ FIXED CODE
public fun init_pool(
    witness: PROTOCOL_OTW,  // Consumed by value - single use only
    ctx: &mut TxContext
) {
    // witness is moved, cannot be called again
}
""",
                references=[
                    "Sui Framework: sui::coin::create_currency",
                    "Pattern: One-Time Witness"
                ]
            ),

            "SUWC-AUTH-04": FixSuggestion(
                defect_id="SUWC-AUTH-04",
                title="Shared Object Permission Bypass",
                recommended_pattern="AccessControlPattern with Runtime Checks",
                code_fix="Add explicit authorization checks for shared objects",
                explanation=(
                    "Shared objects can be accessed by anyone. Functions modifying shared "
                    "state must explicitly verify caller authorization using capability "
                    "checks or ownership validation."
                ),
                example_code="""
// ❌ VULNERABLE CODE
public fun update_shared_config(
    config: &mut SharedConfig,  // Shared - anyone can access!
    new_value: u64
) {
    config.value = new_value;  // No authorization check
}

// ✅ FIXED CODE
public fun update_shared_config(
    admin_cap: &AdminCap,  // Require capability
    config: &mut SharedConfig,
    new_value: u64
) {
    // Verify admin_cap.owner matches config.admin
    assert!(object::id(admin_cap) == config.admin_cap_id, ENotAuthorized);
    config.value = new_value;
}
""",
                references=[
                    "Sui Framework: sui::validator",
                    "Pattern: Shared Object Access Control",
                    "Real-world exploit: Cetus Protocol (2024)"
                ]
            ),

            # ========== SUWC-CONS (2 defects) ==========
            "SUWC-CONS-01": FixSuggestion(
                defect_id="SUWC-CONS-01",
                title="Curve Invariant Violation",
                recommended_pattern="CircuitBreakerPattern with InvariantCheck",
                code_fix="Add pre/post-condition invariant checks",
                explanation=(
                    "Mathematical invariant (e.g., x*y=k in AMM) can break after state changes. "
                    "Add explicit invariant checks before and after critical operations, with "
                    "circuit breaker to pause on violations."
                ),
                example_code="""
// ❌ VULNERABLE CODE
public fun swap(pool: &mut Pool, amount_in: u64): u64 {
    let amount_out = calculate_output(pool, amount_in);
    pool.reserve_x = pool.reserve_x + amount_in;
    pool.reserve_y = pool.reserve_y - amount_out;
    // No invariant check - curve can be violated!
    amount_out
}

// ✅ FIXED CODE with Circuit Breaker
public fun swap(
    pool: &mut Pool, 
    amount_in: u64,
    ctx: &TxContext
): u64 {
    assert!(!pool.paused, EPaused);  // Circuit breaker check

    let k_before = pool.reserve_x * pool.reserve_y;

    let amount_out = calculate_output(pool, amount_in);
    pool.reserve_x = pool.reserve_x + amount_in;
    pool.reserve_y = pool.reserve_y - amount_out;

    let k_after = pool.reserve_x * pool.reserve_y;
    assert!(k_after >= k_before, EInvariantViolation);  // Invariant check

    amount_out
}

public fun emergency_pause(admin: &AdminCap, pool: &mut Pool) {
    pool.paused = true;  // Circuit breaker activation
}
""",
                references=[
                    "Sui Framework: sui::coin",
                    "Pattern: CircuitBreakerPattern",
                    "Technique: InvariantCheck operation"
                ]
            ),

            "SUWC-CONS-02": FixSuggestion(
                defect_id="SUWC-CONS-02",
                title="Vector-Based Denial of Service",
                recommended_pattern="CircuitBreakerPattern with Bounded Iteration",
                code_fix="Add pagination or maximum iteration limits",
                explanation=(
                    "Unbounded iteration over vectors can cause gas exhaustion. Implement "
                    "pagination for large collections or enforce maximum iteration limits "
                    "with circuit breaker fallback."
                ),
                example_code="""
// ❌ VULNERABLE CODE
public fun process_all_users(registry: &mut Registry) {
    let i = 0;
    while (i < vector::length(&registry.users)) {
        // Gas exhaustion if users vector is large!
        process_user(vector::borrow(&registry.users, i));
        i = i + 1;
    }
}

// ✅ FIXED CODE with Pagination
public fun process_users_batch(
    registry: &mut Registry,
    start_index: u64,
    batch_size: u64  // e.g., max 100 per call
) {
    let max_batch = 100;
    assert!(batch_size <= max_batch, EBatchTooLarge);

    let total = vector::length(&registry.users);
    let end = if (start_index + batch_size > total) { 
        total 
    } else { 
        start_index + batch_size 
    };

    let i = start_index;
    while (i < end) {
        process_user(vector::borrow(&registry.users, i));
        i = i + 1;
    }
}
""",
                references=[
                    "Pattern: CircuitBreakerPattern with Pagination Technique",
                    "Operation: UnboundedIteration detection",
                    "Ontology: sui:performsOperation"
                ]
            ),

            # ========== SUWC-TIME (4 defects) ==========
            "SUWC-TIME-01": FixSuggestion(
                defect_id="SUWC-TIME-01",
                title="Premature Release",
                recommended_pattern="TimeIncentivizationPattern with Epoch Checks",
                code_fix="Add epoch-based vesting checks",
                explanation=(
                    "Time-locked assets released before vesting period elapses. Use "
                    "tx_context::epoch() for temporal checks and enforce linear/cliff "
                    "vesting schedules with proper time validation."
                ),
                example_code="""
// ❌ VULNERABLE CODE
public fun claim(wallet: &mut Wallet, ctx: &TxContext): Coin<SUI> {
    let balance = wallet.balance;
    // No time check - can claim immediately!
    coin::take(&mut wallet.balance, balance, ctx)
}

// ✅ FIXED CODE with Time Incentivization
public fun claim(wallet: &mut Wallet, ctx: &TxContext): Coin<SUI> {
    let current_epoch = tx_context::epoch(ctx);
    let elapsed = current_epoch - wallet.start_epoch;

    // Enforce minimum vesting period
    assert!(elapsed >= wallet.vesting_duration, EVestingNotComplete);

    // Calculate claimable amount (linear vesting)
    let claimable = if (elapsed >= wallet.vesting_duration) {
        balance::value(&wallet.balance)  // Fully vested
    } else {
        (balance::value(&wallet.balance) * elapsed) / wallet.vesting_duration
    };

    coin::take(&mut wallet.balance, claimable, ctx)
}
""",
                references=[
                    "Sui Framework: sui::staking_pool (linear.move example)",
                    "Pattern: TimeIncentivizationPattern",
                    "DCR Events: TIStart → TIProceed (condition)"
                ]
            ),

            "SUWC-TIME-02": FixSuggestion(
                defect_id="SUWC-TIME-02",
                title="Indefinite Lock",
                recommended_pattern="EscapabilityPattern",
                code_fix="Add emergency extraction mechanism",
                explanation=(
                    "Assets locked with impossible or missing extraction conditions. Implement "
                    "the Escapability Pattern with authorized upgrade or emergency withdrawal "
                    "mechanism to prevent permanent asset loss."
                ),
                example_code="""
// ❌ VULNERABLE CODE
public fun lock_forever(coin: Coin<SUI>, ctx: &mut TxContext) {
    let locked = LockedCoin { 
        id: object::new(ctx),
        coin: coin,
        // No unlock mechanism - assets locked forever!
    };
    transfer::freeze_object(locked);  // Immutable - cannot be changed
}

// ✅ FIXED CODE with Escapability
public struct LockedCoin has key {
    id: UID,
    coin: Coin<SUI>,
    unlock_epoch: u64,
    owner: address
}

public fun unlock(
    locked: LockedCoin,
    ctx: &TxContext
): Coin<SUI> {
    assert!(tx_context::epoch(ctx) >= locked.unlock_epoch, ETooEarly);
    assert!(tx_context::sender(ctx) == locked.owner, ENotOwner);

    let LockedCoin { id, coin, unlock_epoch: _, owner: _ } = locked;
    object::delete(id);
    coin  // Asset successfully extracted
}

// Emergency escape via upgrade capability
public fun emergency_unlock(
    _upgrade_cap: &UpgradeCap,
    locked: LockedCoin
): Coin<SUI> {
    // Admin can always rescue assets
    let LockedCoin { id, coin, unlock_epoch: _, owner: _ } = locked;
    object::delete(id);
    coin
}
""",
                references=[
                    "Sui Framework: sui::package",
                    "Pattern: EscapabilityPattern",
                    "DCR Events: ESAuthorize → ESEscape"
                ]
            ),

            "SUWC-TIME-03": FixSuggestion(
                defect_id="SUWC-TIME-03",
                title="Timestamp Manipulation",
                recommended_pattern="TimeIncentivizationPattern with Epoch-based Time",
                code_fix="Replace timestamp_ms() with epoch()",
                explanation=(
                    "Using tx_context::timestamp_ms() for time-critical logic is vulnerable "
                    "to validator manipulation. Use tx_context::epoch() for security-critical "
                    "temporal checks, as epochs are consensus-guaranteed."
                ),
                example_code="""
// ❌ VULNERABLE CODE
public fun check_deadline(clock: &Clock, ctx: &TxContext) {
    let now = clock::timestamp_ms(clock);  // DANGER: manipulable by validators
    assert!(now < DEADLINE_MS, EDeadlinePassed);
}

// ✅ FIXED CODE
public fun check_deadline(ctx: &TxContext) {
    let current_epoch = tx_context::epoch(ctx);  // Consensus-guaranteed
    assert!(current_epoch < DEADLINE_EPOCH, EDeadlinePassed);
}

// For display/UI purposes only (not security checks)
public fun get_display_time(ctx: &TxContext): u64 {
    tx_context::timestamp_ms(ctx)  // OK for non-critical use
}
""",
                references=[
                    "Sui Documentation: Time and Randomness",
                    "Operation: TimestampComparison detection",
                    "Best Practice: Use epoch() for security"
                ]
            ),

            "SUWC-TIME-04": FixSuggestion(
                defect_id="SUWC-TIME-04",
                title="Race Between Time Conditions",
                recommended_pattern="TimeIncentivizationPattern with Priority Ordering",
                code_fix="Add transaction ordering or fair queuing",
                explanation=(
                    "Multiple transactions racing on shared vesting/staking pools at epoch "
                    "boundaries. Implement fair queuing or priority mechanisms to prevent "
                    "front-running at temporal boundaries."
                ),
                example_code="""
// ❌ VULNERABLE CODE
public fun claim_reward(
    pool: &mut SharedRewardPool,
    ctx: &TxContext
) {
    let current_epoch = tx_context::epoch(ctx);
    if (current_epoch >= pool.reward_epoch) {
        // Race condition: first caller gets all rewards!
        let reward = pool.total_rewards;
        transfer::public_transfer(
            coin::take(&mut pool.balance, reward, ctx),
            tx_context::sender(ctx)
        );
    }
}

// ✅ FIXED CODE with Fair Distribution
public struct UserStake has store {
    amount: u64,
    stake_epoch: u64,
    claimed: bool  // Track claim status to prevent double-claiming
}

public fun claim_reward(
    user_stake: &mut UserStake,
    pool: &mut SharedRewardPool,
    ctx: &TxContext
) {
    let current_epoch = tx_context::epoch(ctx);
    assert!(current_epoch >= pool.reward_epoch, ETooEarly);

    // Calculate fair share based on user's stake
    let epochs_staked = current_epoch - user_stake.stake_epoch;
    let user_share = (pool.total_rewards * user_stake.amount) / pool.total_staked;

    // Mark as claimed to prevent double-claiming
    assert!(!user_stake.claimed, EAlreadyClaimed);
    user_stake.claimed = true;

    transfer::public_transfer(
        coin::take(&mut pool.balance, user_share, ctx),
        tx_context::sender(ctx)
    );
}
""",
                references=[
                    "Pattern: Fair Queuing",
                    "Operation: TemporalConstraint",
                    "Addresses: SUWC-TIME-04 + SUWC-AUTH-04"
                ]
            ),

            # ========== SUWC-RES (3 defects) ==========
            "SUWC-RES-01": FixSuggestion(
                defect_id="SUWC-RES-01",
                title="Hot Potato Drop",
                recommended_pattern="Hot Potato Pattern",
                code_fix="Enforce linear types for transaction receipts",
                explanation=(
                    "Receipt struct with 'drop' ability bypasses forced execution obligation. "
                    "Remove 'drop' from hot potato structs to ensure they must be consumed "
                    "by calling a specific function."
                ),
                example_code="""
// ❌ VULNERABLE CODE
public struct Receipt has drop {  // DANGER: can be ignored
    amount: u64
}

public fun step1(): Receipt {
    Receipt { amount: 100 }
}

public fun step2(receipt: Receipt) {
    // Should be called but can be skipped because Receipt has 'drop'
}

// ✅ FIXED CODE
public struct Receipt {  // No 'drop' - must be consumed!
    amount: u64
}

public fun step1(): Receipt {
    Receipt { amount: 100 }
}

public fun step2(receipt: Receipt) {
    let Receipt { amount } = receipt;  // MUST be called to destroy Receipt
    // Process amount...
}
""",
                references=[
                    "Pattern: Hot Potato Pattern",
                    "Sui Framework: sui::coin::CoinBalance",
                    "Type System: Linear types enforcement"
                ]
            ),

            "SUWC-RES-02": FixSuggestion(
                defect_id="SUWC-RES-02",
                title="Object Locking (Roach Motel)",
                recommended_pattern="EscapabilityPattern",
                code_fix="Add extraction mechanism for wrapped objects",
                explanation=(
                    "Object wrapped permanently with no extraction mechanism (Roach Motel: "
                    "check in but never check out). Implement unwrap function or use dynamic "
                    "fields that can be removed."
                ),
                example_code="""
// ❌ VULNERABLE CODE
public struct Wrapper has key {
    id: UID,
    inner: SomeObject  // Trapped forever!
}

public fun wrap(obj: SomeObject, ctx: &mut TxContext) {
    let wrapper = Wrapper { 
        id: object::new(ctx), 
        inner: obj 
    };
    transfer::freeze_object(wrapper);  // No way to extract inner!
}

// ✅ FIXED CODE with Escapability
public struct Wrapper has key {
    id: UID,
    inner: Option<SomeObject>  // Use Option for optional extraction
}

public fun wrap(obj: SomeObject, ctx: &mut TxContext): Wrapper {
    Wrapper { 
        id: object::new(ctx), 
        inner: option::some(obj) 
    }
}

public fun unwrap(wrapper: Wrapper): SomeObject {
    let Wrapper { id, inner } = wrapper;
    object::delete(id);
    option::destroy_some(inner)  // Successfully extracted!
}

// Alternative: Use dynamic fields (can be removed)
public fun wrap_dynamic(
    wrapper: &mut Wrapper,
    obj: SomeObject
) {
    dynamic_field::add(&mut wrapper.id, b"inner", obj);
}

public fun unwrap_dynamic(wrapper: &mut Wrapper): SomeObject {
    dynamic_field::remove(&mut wrapper.id, b"inner")  // Can be extracted
}
""",
                references=[
                    "Pattern: EscapabilityPattern",
                    "Sui Framework: sui::dynamic_field",
                    "SUWC: Prevents permanent asset loss"
                ]
            ),

            "SUWC-RES-03": FixSuggestion(
                defect_id="SUWC-RES-03",
                title="Permanent Locking",
                recommended_pattern="EscapabilityPattern with Emergency Unlock",
                code_fix="Add time-based or admin unlock mechanism",
                explanation=(
                    "No way to extract assets from locked state. Similar to SUWC-TIME-02 but "
                    "focuses on resource management. Add either time-based unlock conditions "
                    "or emergency admin escape mechanism using UpgradeCap."
                ),
                example_code="""
// ❌ VULNERABLE CODE
public struct Vault has key {
    id: UID,
    balance: Balance<SUI>
    // No unlock mechanism!
}

public fun deposit(vault: &mut Vault, coin: Coin<SUI>) {
    coin::put(&mut vault.balance, coin);
    // Deposits work, but withdrawals are impossible!
}

// ✅ FIXED CODE with Dual Escape Mechanisms
public struct Vault has key {
    id: UID,
    balance: Balance<SUI>,
    owner: address,
    unlock_epoch: u64
}

// Time-based escape
public fun withdraw_after_unlock(
    vault: &mut Vault,
    amount: u64,
    ctx: &TxContext
): Coin<SUI> {
    assert!(tx_context::sender(ctx) == vault.owner, ENotOwner);
    assert!(tx_context::epoch(ctx) >= vault.unlock_epoch, EStillLocked);
    coin::take(&mut vault.balance, amount, ctx)
}

// Admin escape mechanism
public fun emergency_withdraw(
    _upgrade_cap: &UpgradeCap,
    vault: &mut Vault,
    amount: u64,
    ctx: &TxContext
): Coin<SUI> {
    // Admin can always rescue funds
    coin::take(&mut vault.balance, amount, ctx)
}

// Upgrade escape: migrate to new version
public fun migrate_to_v2(
    _upgrade_cap: &UpgradeCap,
    old_vault: Vault,
    ctx: &mut TxContext  // Added missing context parameter
): VaultV2 {
    let Vault { id, balance, owner, unlock_epoch } = old_vault;
    object::delete(id);
    // Create new version with fixed logic
    VaultV2 { 
        id: object::new(ctx),
        balance,
        owner,
        unlock_epoch,
        emergency_unlock_enabled: true  // New feature
    }
}
""",
                references=[
                    "Sui Framework: sui::package (UpgradeCap)",
                    "Pattern: EscapabilityPattern",
                    "Addresses: SUWC-RES-03 + SUWC-TIME-02"
                ]
            ),
        }

    def suggest_fix(self, detection: VulnerabilityDetection) -> FixSuggestion:
        """Get fix suggestion for detected vulnerability"""
        if detection.defect_id not in self.fix_database:
            return FixSuggestion(
                defect_id=detection.defect_id,
                title="Unknown Defect",
                recommended_pattern="Manual Review Required",
                code_fix="No automated fix available",
                explanation="This defect is not in the SUWC taxonomy.",
                example_code="",
                references=[]
            )

        return self.fix_database[detection.defect_id]

    def generate_fix_report(self, detections: List[VulnerabilityDetection], 
                           output_path: str = "fix_report.md"):
        """Generate comprehensive fix report in Markdown"""

        # Group by category
        by_category = {}
        for det in detections:
            cat = det.category.value
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(det)

        # Generate report
        report = []
        report.append("# 🔒 Automated Security Fix Report")
        report.append(f"\n**Total Vulnerabilities Detected:** {len(detections)}\n")
        report.append("---\n")

        for category, dets in sorted(by_category.items()):
            report.append(f"## {category}: {len(dets)} issues\n")

            for det in sorted(dets, key=lambda x: x.severity.value, reverse=True):
                fix = self.suggest_fix(det)

                report.append(f"### 🚨 {fix.title}")
                report.append(f"**Defect ID:** `{det.defect_id}`  ")
                report.append(f"**Severity:** `{det.severity.value}`  ")
                report.append(f"**Location:** `{det.function_name}` (line {det.line_number or 'N/A'})  ")
                report.append(f"**Description:** {det.description}\n")

                report.append(f"**🎯 Recommended Pattern:** `{fix.recommended_pattern}`\n")
                report.append(f"**📝 Explanation:**\n{fix.explanation}\n")

                report.append(f"**💡 Code Fix:**\n{fix.example_code}\n")

                if fix.references:
                    report.append("**📚 References:**")
                    for ref in fix.references:
                        report.append(f"- {ref}")
                    report.append("")

                report.append("---\n")

        # Write report
        report_content = "\n".join(report)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)

        return output_path

    def get_pattern_mapping(self, defect_id: str) -> Optional[str]:
        """Get which design pattern addresses a specific defect"""
        pattern_map = {
            "SUWC-AUTH-01": "AccessControlPattern",
            "SUWC-AUTH-02": "AccessControlPattern",
            "SUWC-AUTH-03": "One-Time Witness Pattern",
            "SUWC-AUTH-04": "AccessControlPattern",
            "SUWC-CONS-01": "CircuitBreakerPattern",
            "SUWC-CONS-02": "CircuitBreakerPattern",
            "SUWC-TIME-01": "TimeIncentivizationPattern",
            "SUWC-TIME-02": "EscapabilityPattern",
            "SUWC-TIME-03": "TimeIncentivizationPattern",
            "SUWC-TIME-04": "TimeIncentivizationPattern + AccessControlPattern",
            "SUWC-RES-01": "Linear Types (Type System)",
            "SUWC-RES-02": "EscapabilityPattern",
            "SUWC-RES-03": "EscapabilityPattern + TimeIncentivizationPattern",
        }
        return pattern_map.get(defect_id)

# Example usage
if __name__ == "__main__":
    suggester = AutomatedFixSuggester()

    # Example detection
    detection = VulnerabilityDetection(
        defect_id="SUWC-AUTH-01",
        category=VulnerabilityCategory.AUTH,
        severity=SeverityLevel.CRITICAL,
        function_name="withdraw",
        line_number=42,
        description="Function lacks signer verification",
        evidence="No capability check found"
    )

    # Get fix
    fix = suggester.suggest_fix(detection)
    print(f"Fix for {detection.defect_id}:")
    print(f"Pattern: {fix.recommended_pattern}")
    print(f"\nExplanation: {fix.explanation}")
