#![cfg_attr(not(feature = "std"), no_std)]

//! Provider identity, lifecycle, and stake bonding (ADR-036).
//!
//! **Bonding.** [`Pallet::bond_stake`]/[`Pallet::request_unbond`]/
//! [`Pallet::withdraw_unbonded`] are self-service, deliberately decoupled
//! from [`Pallet::register_provider_for`] (ADR-036 §1): the Control Plane
//! bridge account verifies a provider's off-chain identity and registers it,
//! but never fronts its collateral -- exactly the anti-pattern ADR-029 §3
//! already rejected for tenant escrow funding. A bonded provider whose stake
//! stays at or above [`Config::MinStake`] may reach [`ProviderStatus::Active`];
//! [`Pallet::set_status`]'s `Verified -> Active` edge is the only transition
//! this ADR gates.
//!
//! **Reserve-balance contamination guard, third edge.** This pallet, like
//! `pallet-network-validator` and `pallet-escrow`, reserves against the
//! same untagged, per-account `pallet_balances` reserved balance (this
//! codebase predates `fungible::MutateHold`/`HoldReason`). Bonding is a
//! third role reserving into that pool. [`Pallet::bond_stake`] refuses a
//! caller that currently has funds locked in an open `pallet-escrow` escrow
//! as `payer` ([`EscrowPayerInspector`]) or that is a registered Network
//! Validator ([`ValidatorRegistrationInspector`]) -- the same guard shape
//! `pallet-network-validator::register_validator` and
//! `pallet-escrow::fund_escrow` already carry for each other. Symmetrically,
//! this pallet exposes [`ProviderBondInspector`] for those two pallets to
//! consume, closing the third edge of the same contamination class: an
//! `AccountId` may hold at most one of {Network Validator, escrow payer,
//! bonded provider} at a time.
//!
//! **Slash-then-exit race.** [`Pallet::request_unbond`] and
//! [`Pallet::withdraw_unbonded`] both refuse to proceed while
//! `pallet-provider-slashing` has a live pending slash against the caller
//! ([`ProviderSlashInspector`]), re-checked at withdrawal time (not only at
//! request time) because a breach can be detected after unbonding has
//! already begun.

pub use pallet::*;

use frame_support::{
    sp_runtime::traits::{Saturating, Zero},
    traits::{Currency, EnsureOrigin, Get, ReservableCurrency},
    weights::Weight,
};
use frame_system::pallet_prelude::*;

/// Narrow interface used by pallets that only need to inspect provider status.
pub trait ProviderInspector<AccountId> {
    fn is_registered(provider: &AccountId) -> bool;
    fn is_active(provider: &AccountId) -> bool;
}

/// Narrow, read-only check for whether an account currently has funds
/// locked in an open `pallet-escrow` escrow as `payer`. Backs
/// [`Pallet::bond_stake`]'s reserve-contamination guard -- mirrors
/// `pallet-network-validator::EscrowPayerInspector` exactly (ADR-036 §5).
pub trait EscrowPayerInspector<AccountId> {
    fn has_open_escrow(payer: &AccountId) -> bool;
}

impl<AccountId> EscrowPayerInspector<AccountId> for () {
    fn has_open_escrow(_: &AccountId) -> bool {
        false
    }
}

/// Narrow, read-only check for whether an account is currently a
/// registered Network Validator, regardless of status. Backs
/// [`Pallet::bond_stake`]'s reserve-contamination guard -- mirrors
/// `pallet-escrow::ValidatorRegistrationInspector` exactly (ADR-036 §5).
pub trait ValidatorRegistrationInspector<AccountId> {
    fn is_registered(account: &AccountId) -> bool;
}

impl<AccountId> ValidatorRegistrationInspector<AccountId> for () {
    fn is_registered(_: &AccountId) -> bool {
        false
    }
}

/// Narrow, read-only check for whether an account has a live pending slash
/// in `pallet-provider-slashing`, in any dimension. Backs
/// [`Pallet::request_unbond`]/[`Pallet::withdraw_unbonded`]'s
/// slash-then-exit race guard (ADR-036 §6).
pub trait ProviderSlashInspector<AccountId> {
    fn has_pending_slash(provider: &AccountId) -> bool;
}

impl<AccountId> ProviderSlashInspector<AccountId> for () {
    fn has_pending_slash(_: &AccountId) -> bool {
        false
    }
}

/// Narrow, read-only check for whether a provider currently has an open
/// bond (funds reserved as provider stake, in `Active` or `Exiting`
/// status). Exposed by this pallet (ADR-036 §1/§5) for
/// `pallet-network-validator::register_validator` and
/// `pallet-escrow::fund_escrow` to consume directly: an account with funds
/// locked in an open provider bond may not also become a Network Validator
/// or an escrow payer, closing the third edge of the reserve-balance
/// contamination class those two pallets' own inspector traits already
/// closed for each other.
pub trait ProviderBondInspector<AccountId> {
    fn has_open_bond(provider: &AccountId) -> bool;
}

impl<AccountId> ProviderBondInspector<AccountId> for () {
    fn has_open_bond(_: &AccountId) -> bool {
        false
    }
}

pub trait WeightInfo {
    fn register_provider() -> Weight;
    fn register_provider_for() -> Weight;
    fn set_status() -> Weight;
    fn bond_stake() -> Weight;
    fn request_unbond() -> Weight;
    fn withdraw_unbonded() -> Weight;
}

impl WeightInfo for () {
    fn register_provider() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn register_provider_for() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn set_status() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn bond_stake() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn request_unbond() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn withdraw_unbonded() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;

    pub type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        type RegistrationOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        type StatusOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        /// Bonds a provider's stake (ADR-036 §1). Reuses the same
        /// `pallet_balances` instance already backing Network Validator
        /// stake and escrow `payer` reservations -- no new asset pallet.
        type Currency: ReservableCurrency<Self::AccountId>;
        /// Backs [`Pallet::bond_stake`]'s reserve-contamination guard; the
        /// runtime wires this to `pallet-escrow::PayerOpenEscrowCount`.
        type EscrowInspector: EscrowPayerInspector<Self::AccountId>;
        /// Backs [`Pallet::bond_stake`]'s reserve-contamination guard; the
        /// runtime wires this to `pallet-network-validator::Validators`.
        type ValidatorInspector: ValidatorRegistrationInspector<Self::AccountId>;
        /// Backs [`Pallet::request_unbond`]/[`Pallet::withdraw_unbonded`]'s
        /// slash-then-exit race guard; the runtime wires this to
        /// `pallet-provider-slashing::PendingSlashes`.
        type SlashInspector: ProviderSlashInspector<Self::AccountId>;
        /// Minimum bonded stake a provider must hold to reach
        /// [`ProviderStatus::Active`] (ADR-036 §3: `MinProviderStake`), and
        /// the minimum amount a first [`Pallet::bond_stake`] call must
        /// reserve. Top-ups above this floor are unrestricted.
        #[pallet::constant]
        type MinStake: Get<BalanceOf<Self>>;
        /// Blocks a bond stays reserved-but-inert after
        /// [`Pallet::request_unbond`] before [`Pallet::withdraw_unbonded`]
        /// may release it.
        #[pallet::constant]
        type UnbondingPeriod: Get<BlockNumberFor<Self>>;
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[derive(
        Clone,
        Copy,
        Decode,
        DecodeWithMemTracking,
        Encode,
        Eq,
        MaxEncodedLen,
        PartialEq,
        Debug,
        TypeInfo,
    )]
    pub enum ProviderStatus {
        Registered,
        Verified,
        Active,
        Suspended,
        Removed,
    }

    #[derive(
        Clone, Decode, DecodeWithMemTracking, Encode, Eq, MaxEncodedLen, PartialEq, Debug, TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    pub struct Provider<T: Config> {
        pub owner: T::AccountId,
        pub public_key: [u8; 32],
        pub status: ProviderStatus,
    }

    /// Lifecycle of a provider's bond (ADR-036 §1), mirroring
    /// `pallet-network-validator::ValidatorStatus`'s shape: stake stays
    /// reserved (and therefore still slashable) throughout `Exiting`, only
    /// released by [`Pallet::withdraw_unbonded`] once
    /// [`Config::UnbondingPeriod`] has elapsed.
    #[derive(
        Clone, Encode, Decode, DecodeWithMemTracking, Eq, MaxEncodedLen, PartialEq, Debug, TypeInfo,
    )]
    pub enum BondStatus<BlockNumber> {
        Active,
        Exiting { available_at: BlockNumber },
    }

    #[derive(
        Clone, Encode, Decode, DecodeWithMemTracking, Eq, MaxEncodedLen, PartialEq, Debug, TypeInfo,
    )]
    pub struct BondRecord<Balance, BlockNumber> {
        pub stake: Balance,
        pub status: BondStatus<BlockNumber>,
    }

    #[pallet::storage]
    #[pallet::getter(fn providers)]
    pub type Providers<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, Provider<T>, OptionQuery>;

    #[pallet::storage]
    pub type ProviderByKey<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], T::AccountId, OptionQuery>;

    /// Provider stake bonds (ADR-036 §1). A present entry means the
    /// provider's stake is currently reserved -- in `Active` status it
    /// backs the provider's `Active` status directly; in `Exiting` it
    /// remains reserved, and therefore still reachable by
    /// `pallet-provider-slashing::execute_slash`, until
    /// [`Pallet::withdraw_unbonded`] actually releases it.
    #[pallet::storage]
    #[pallet::getter(fn provider_bonds)]
    pub type ProviderBonds<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BondRecord<BalanceOf<T>, BlockNumberFor<T>>,
        OptionQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ProviderRegistered {
            provider: T::AccountId,
        },
        StatusChanged {
            provider: T::AccountId,
            status: ProviderStatus,
        },
        /// A first bond or a top-up. `total` is the bond's new stake after
        /// this call.
        BondIncreased {
            provider: T::AccountId,
            added: BalanceOf<T>,
            total: BalanceOf<T>,
        },
        UnbondRequested {
            provider: T::AccountId,
            available_at: BlockNumberFor<T>,
        },
        BondWithdrawn {
            provider: T::AccountId,
            amount: BalanceOf<T>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        AlreadyRegistered,
        PublicKeyAlreadyRegistered,
        InvalidPublicKey,
        ProviderNotFound,
        InvalidStatusTransition,
        /// `Verified -> Active` requires a bond of at least `MinStake`
        /// (ADR-036 §1).
        InsufficientBondForActive,
        /// A first `bond_stake` call must reserve at least `MinStake`.
        InsufficientStake,
        InsufficientFreeBalance,
        /// `bond_stake`/`request_unbond` called while already `Exiting`.
        AlreadyExiting,
        /// No bond exists for this account.
        NotBonded,
        /// `withdraw_unbonded` called on a bond that is not `Exiting`.
        NotExiting,
        /// `UnbondingPeriod` has not yet elapsed.
        UnbondingNotComplete,
        UnbondingPeriodOverflow,
        /// A live pending slash exists in `pallet-provider-slashing` for
        /// this account -- exit is blocked until it resolves (ADR-036 §6).
        SlashPending,
        /// The caller currently has funds locked in an open `pallet-escrow`
        /// escrow as `payer` (see [`super::EscrowPayerInspector`]).
        PayerHasOpenEscrow,
        /// The caller is currently a registered Network Validator (see
        /// [`super::ValidatorRegistrationInspector`]).
        CallerIsRegisteredValidator,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::register_provider())]
        pub fn register_provider(origin: OriginFor<T>, public_key: [u8; 32]) -> DispatchResult {
            let owner = ensure_signed(origin)?;
            Self::do_register_provider(owner, public_key)
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::set_status())]
        pub fn set_status(
            origin: OriginFor<T>,
            provider: T::AccountId,
            status: ProviderStatus,
        ) -> DispatchResult {
            T::StatusOrigin::ensure_origin(origin)?;
            Providers::<T>::try_mutate(&provider, |entry| -> DispatchResult {
                let record = entry.as_mut().ok_or(Error::<T>::ProviderNotFound)?;
                ensure!(
                    Self::valid_transition(record.status, status),
                    Error::<T>::InvalidStatusTransition
                );
                // ADR-036 §1: gate only the Verified -> Active edge on a
                // sufficient bond. A provider with no bond, or one that has
                // fallen below MinStake (e.g. via a slash), cannot become
                // Active and therefore cannot be scheduled a new lease.
                if record.status == ProviderStatus::Verified && status == ProviderStatus::Active {
                    let bonded = ProviderBonds::<T>::get(&provider)
                        .map(|bond| bond.stake)
                        .unwrap_or_default();
                    ensure!(
                        bonded >= T::MinStake::get(),
                        Error::<T>::InsufficientBondForActive
                    );
                }
                record.status = status;
                Ok(())
            })?;
            Self::deposit_event(Event::StatusChanged { provider, status });
            Ok(())
        }

        /// Register a provider account on behalf of an Agent after the configured
        /// registration authority has verified its off-chain identity proof.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::register_provider_for())]
        pub fn register_provider_for(
            origin: OriginFor<T>,
            provider: T::AccountId,
            public_key: [u8; 32],
        ) -> DispatchResult {
            T::RegistrationOrigin::ensure_origin(origin)?;
            Self::do_register_provider(provider, public_key)
        }

        /// Bond (or top up) the caller's own provider stake (ADR-036 §1).
        /// Self-service, deliberately decoupled from registration: the
        /// caller must already be a registered provider, but no privileged
        /// origin is involved. The first call must reserve at least
        /// `MinStake`; subsequent top-ups are unrestricted.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::bond_stake())]
        pub fn bond_stake(origin: OriginFor<T>, amount: BalanceOf<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                Providers::<T>::contains_key(&who),
                Error::<T>::ProviderNotFound
            );
            // Reserve-contamination guard (ADR-036 §5): both the other two
            // roles already refuse an account that holds this one; bonding
            // refuses an account that already holds either of them.
            ensure!(
                !T::EscrowInspector::has_open_escrow(&who),
                Error::<T>::PayerHasOpenEscrow
            );
            ensure!(
                !T::ValidatorInspector::is_registered(&who),
                Error::<T>::CallerIsRegisteredValidator
            );

            let total = ProviderBonds::<T>::try_mutate(
                &who,
                |maybe_record| -> Result<BalanceOf<T>, DispatchError> {
                    match maybe_record {
                        None => {
                            ensure!(amount >= T::MinStake::get(), Error::<T>::InsufficientStake);
                            T::Currency::reserve(&who, amount)
                                .map_err(|_| Error::<T>::InsufficientFreeBalance)?;
                            *maybe_record = Some(BondRecord {
                                stake: amount,
                                status: BondStatus::Active,
                            });
                            Ok(amount)
                        }
                        Some(record) => {
                            ensure!(
                                !matches!(record.status, BondStatus::Exiting { .. }),
                                Error::<T>::AlreadyExiting
                            );
                            T::Currency::reserve(&who, amount)
                                .map_err(|_| Error::<T>::InsufficientFreeBalance)?;
                            record.stake = record.stake.saturating_add(amount);
                            Ok(record.stake)
                        }
                    }
                },
            )?;
            Self::deposit_event(Event::BondIncreased {
                provider: who,
                added: amount,
                total,
            });
            Ok(())
        }

        /// Begin unbonding. The stake stays reserved (and the provider
        /// keeps its existing `ProviderStatus` -- this call does not force
        /// a status transition) until `UnbondingPeriod` has elapsed. Fails
        /// if a live pending slash exists (ADR-036 §6).
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::request_unbond())]
        pub fn request_unbond(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                !T::SlashInspector::has_pending_slash(&who),
                Error::<T>::SlashPending
            );
            let available_at = ProviderBonds::<T>::try_mutate(
                &who,
                |maybe_record| -> Result<BlockNumberFor<T>, DispatchError> {
                    let record = maybe_record.as_mut().ok_or(Error::<T>::NotBonded)?;
                    ensure!(
                        !matches!(record.status, BondStatus::Exiting { .. }),
                        Error::<T>::AlreadyExiting
                    );
                    let now = frame_system::Pallet::<T>::block_number();
                    let available_at = now
                        .checked_add(&T::UnbondingPeriod::get())
                        .ok_or(Error::<T>::UnbondingPeriodOverflow)?;
                    record.status = BondStatus::Exiting { available_at };
                    Ok(available_at)
                },
            )?;
            Self::deposit_event(Event::UnbondRequested {
                provider: who,
                available_at,
            });
            Ok(())
        }

        /// Release the reserved stake once unbonding has completed and
        /// remove the bond record. Re-checks for a live pending slash (not
        /// only at `request_unbond` time -- ADR-036 §6): a breach can be
        /// detected after unbonding has already begun.
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::withdraw_unbonded())]
        pub fn withdraw_unbonded(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let record = ProviderBonds::<T>::get(&who).ok_or(Error::<T>::NotBonded)?;
            match record.status {
                BondStatus::Exiting { available_at } => {
                    let now = frame_system::Pallet::<T>::block_number();
                    ensure!(now >= available_at, Error::<T>::UnbondingNotComplete);
                }
                BondStatus::Active => return Err(Error::<T>::NotExiting.into()),
            }
            ensure!(
                !T::SlashInspector::has_pending_slash(&who),
                Error::<T>::SlashPending
            );
            T::Currency::unreserve(&who, record.stake);
            ProviderBonds::<T>::remove(&who);
            Self::deposit_event(Event::BondWithdrawn {
                provider: who,
                amount: record.stake,
            });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn do_register_provider(owner: T::AccountId, public_key: [u8; 32]) -> DispatchResult {
            ensure!(public_key != [0; 32], Error::<T>::InvalidPublicKey);
            ensure!(
                !Providers::<T>::contains_key(&owner),
                Error::<T>::AlreadyRegistered
            );
            ensure!(
                !ProviderByKey::<T>::contains_key(public_key),
                Error::<T>::PublicKeyAlreadyRegistered
            );

            Providers::<T>::insert(
                &owner,
                Provider::<T> {
                    owner: owner.clone(),
                    public_key,
                    status: ProviderStatus::Registered,
                },
            );
            ProviderByKey::<T>::insert(public_key, &owner);
            Self::deposit_event(Event::ProviderRegistered { provider: owner });
            Ok(())
        }

        fn valid_transition(from: ProviderStatus, to: ProviderStatus) -> bool {
            matches!(
                (from, to),
                (ProviderStatus::Registered, ProviderStatus::Verified)
                    | (ProviderStatus::Verified, ProviderStatus::Active)
                    | (ProviderStatus::Active, ProviderStatus::Suspended)
                    | (ProviderStatus::Suspended, ProviderStatus::Active)
                    | (ProviderStatus::Registered, ProviderStatus::Removed)
                    | (ProviderStatus::Verified, ProviderStatus::Removed)
                    | (ProviderStatus::Active, ProviderStatus::Removed)
                    | (ProviderStatus::Suspended, ProviderStatus::Removed)
            )
        }

        /// ADR-036 §6: internal, non-extrinsic entry point used by
        /// `pallet-provider-slashing::execute_slash`/`resolve_slash_appeal`
        /// to remove bonded stake -- mirrors
        /// `pallet-reputation::set_dimension_score`'s "internal-only, not a
        /// `#[pallet::call]`" pattern, so this pallet stays the only writer
        /// of `ProviderBonds` regardless of which pallet triggers a change.
        ///
        /// Mirrors `pallet-network-validator::slash_round_submitters`'s
        /// saturating pattern exactly: `slash_reserved` is capped at
        /// whatever is actually reserved regardless of `requested`, the
        /// returned shortfall tells the caller what was *not* removed, so
        /// `requested - shortfall` is the real amount taken; `ProviderBonds`
        /// is `saturating_sub`'d by that real amount, never underflows,
        /// never exceeds the bond. If the post-slash stake falls below
        /// `MinStake`, the provider is force-suspended in the same call
        /// (reusing the `Active -> Suspended` edge `valid_transition`
        /// already allows) so a now-under-collateralized provider cannot
        /// keep taking new leases while a status change is pending.
        ///
        /// Returns `(amount_actually_slashed, force_suspended)`.
        pub fn slash_bond(
            provider: &T::AccountId,
            requested: BalanceOf<T>,
        ) -> (BalanceOf<T>, bool) {
            let Some(mut record) = ProviderBonds::<T>::get(provider) else {
                return (Zero::zero(), false);
            };
            let (imbalance, shortfall) = T::Currency::slash_reserved(provider, requested);
            drop(imbalance); // burned: no `resolve` call, matching ADR-036 §3
            let slashed = requested.saturating_sub(shortfall);
            if slashed.is_zero() {
                return (Zero::zero(), false);
            }
            record.stake = record.stake.saturating_sub(slashed);
            let should_suspend = record.stake < T::MinStake::get();
            ProviderBonds::<T>::insert(provider, record);

            let mut force_suspended = false;
            if should_suspend {
                Providers::<T>::mutate(provider, |maybe| {
                    if let Some(entry) = maybe.as_mut() {
                        if entry.status == ProviderStatus::Active {
                            entry.status = ProviderStatus::Suspended;
                            force_suspended = true;
                        }
                    }
                });
                if force_suspended {
                    Self::deposit_event(Event::StatusChanged {
                        provider: provider.clone(),
                        status: ProviderStatus::Suspended,
                    });
                }
            }
            (slashed, force_suspended)
        }
    }

    impl<T: Config> ProviderInspector<T::AccountId> for Pallet<T> {
        fn is_registered(provider: &T::AccountId) -> bool {
            Providers::<T>::contains_key(provider)
        }

        fn is_active(provider: &T::AccountId) -> bool {
            Providers::<T>::get(provider)
                .is_some_and(|record| record.status == ProviderStatus::Active)
        }
    }

    impl<T: Config> super::ProviderBondInspector<T::AccountId> for Pallet<T> {
        fn has_open_bond(provider: &T::AccountId) -> bool {
            ProviderBonds::<T>::contains_key(provider)
        }
    }
}

#[cfg(test)]
mod tests;
