use crate::{types};
use frame_support::{
    decl_event, decl_module, decl_storage,
    dispatch::{Decode, DispatchError, DispatchResult, Encode, Vec},
    ensure,
    traits::{Currency, ExistenceRequirement},
    weights::Weight,
};
use myna::crypto;
use sp_std::vec;
use system::{ensure_none, ensure_root, ensure_signed};

use core::convert::TryInto;
use sp_core::{Blake2Hasher, Hasher};
use sp_runtime::traits::CheckedDiv;

pub const MAX_VOTE_BALANCE_PER_TERM: types::Balance = 10000;
/// The module's configuration trait.
pub trait Trait: balances::Trait {
    // TODO: Add other types and constants required configure this module.
    /// The overarching event type.
    type Event: From<Event> + Into<<Self as system::Trait>::Event>;
}

// This module's storage items.
decl_storage! {
    trait Store for Module<T: Trait> as MynaChainModule {
        AccountCount get(fn account_count): u64;
        AccountEnumerator get(fn account_enum): map u64 => types::AccountId;
        Accounts get(fn account): map types::AccountId => types::Account;
        RawBalance get(fn balance): map types::AccountId => types::Balance;
        TermNumber get(fn term_number): types::TermNumber;
        CumulativeVotes get(fn votes_cum): map types::TermNumber => types::Balance; // 投票の累積和。ちなみにゲッターのcumはCumulativeのprefixです。念の為。
    }
}

decl_event!(
    pub enum Event {
        AccountAdd(types::AccountId),
        Transferred(types::AccountId, types::AccountId, types::Balance),
        Minted(types::AccountId, types::Balance),
        Voted(types::AccountId, types::Balance),
        Written(types::AccountId),
        NextTerm(types::TermNumber),
        AlwaysOk,
    }
);
decl_module! {
    /// The module declaration.
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        pub fn go(origin, tx: types::SignedData) -> DispatchResult{
            match tx.clone().tbs {
                types::Tx::CreateAccount(t) => Self::create_account(tx, t),
                types::Tx::Send(t) => Self::send(tx, t),
                types::Tx::Mint(t) => Self::mint(tx, t),
                types::Tx::Vote(t) => Self::vote(tx, t),
                types::Tx::Write(t) => Self::write(tx, t),
                types::Tx::NextTerm(t) => Self::next_term(tx,t),
                _ => Ok(())
            }
        }
    }
}

impl<T: Trait> Module<T> {
    /// Create an Account
    /// nonce must be zero
    /// id must be zero
    pub fn create_account(tx: types::SignedData, tbs: types::TxCreateAccount) -> DispatchResult {
        ensure!(tbs.nonce == 0, "Nonce is not zero");

        tbs.check_ca()?;

        let sig = &tx.signature;
        let pubkey = crypto::extract_pubkey(&tbs.cert[..]).map_err(|_| "failed to get pubkey")?;
        tx.verify(pubkey)?;
        Self::insert_account(tbs.cert)?;
        Ok(())
    }

    pub fn send(tx: types::SignedData, tbs: types::TxSend) -> DispatchResult {
        let to = tbs.to;
        let from = Self::ensure_rsa_signed(&tx)?;
        let amount = tbs.amount;
        Self::transfer(from, to, amount)?;
        Self::increment_nonce(from)?;
        Ok(())
    }
    pub fn mint(tx: types::SignedData, tbs: types::TxMint) -> DispatchResult {
        return Err(sp_runtime::DispatchError::Other("disabled"));
    }
    pub fn vote(tx: types::SignedData, tbs: types::TxVote) -> DispatchResult {
        return Err(sp_runtime::DispatchError::Other("disabled"));
    }
    pub fn next_term(tx: types::SignedData, tbs: types::TxNextTerm) -> DispatchResult {
        let from = Self::ensure_rsa_signed(&tx)?;
        let cur_term = Self::term_number();
        let new_term = cur_term + 1;
        
        let final_votes = CumulativeVotes::get(cur_term);
        CumulativeVotes::insert(new_term, final_votes);
        
        TermNumber::put(new_term);
        Self::deposit_event(Event::NextTerm(new_term));
        Ok(())
    }

    pub fn write(tx: types::SignedData, tbs: types::TxWrite) -> DispatchResult {
        let from = Self::ensure_rsa_signed(&tx)?;
        let mut account = Accounts::get(from);
        account.data = tbs.data;
        Accounts::insert(from, account);
        Self::increment_nonce(from)?;
        Self::deposit_event(Event::Written(from));
        Ok(())
    }
}
// module func starts here
impl<T: Trait> Module<T> {
    pub fn insert_account(cert: Vec<u8>) -> DispatchResult {
        let new_account_id = Blake2Hasher::hash(&cert[..]);

        ensure!(!Accounts::exists(new_account_id), "Account already exists");

        let new_count = AccountCount::get();

        let new_account = types::Account {
            cert,
            id: new_account_id,
            nonce: 0,
            data: vec![],
            created_at: Self::term_number()
        };
        Accounts::insert(new_account_id, new_account);
        AccountEnumerator::insert(new_count, new_account_id);
        AccountCount::mutate(|t| *t += 1);
        RawBalance::insert(new_account_id, 1000000);
        Self::deposit_event(Event::AccountAdd(new_account_id));

        Ok(())
    }
    pub fn ensure_rsa_signed(tx: &types::SignedData) -> Result<types::AccountId, &'static str> {
        ensure!(Accounts::exists(tx.id), "Account not found");
        let account = Accounts::get(tx.id);
        let pubkey =
            crypto::extract_pubkey(&account.cert[..]).map_err(|_| "failed to get pubkey")?;
        tx.verify(pubkey)?;
        Ok(account.id)
    }

    pub fn transfer(
        from: types::AccountId,
        to: types::AccountId,
        amount: types::Balance,
    ) -> DispatchResult {
        ensure!(Accounts::exists(from), "Account not found");
        ensure!(Accounts::exists(to), "Account not found");

        let new_compbal_from = Self::compute_balance(from)?
            .checked_sub(amount)
            .ok_or("underflow")?;
        ensure!(new_compbal_from >= 0, "Insufficient Balance");
        Self::compute_balance(to)?
            .checked_add(amount)
            .ok_or("Overflow")?;

        let new_rawbal_to = RawBalance::get(to) + amount;
        let new_rawbal_from = RawBalance::get(from) - amount;

        RawBalance::insert(from, new_rawbal_from);
        RawBalance::insert(to, new_rawbal_to);
        Self::deposit_event(Event::Transferred(from, to, amount));
        Ok(())
    }

    pub fn increment_nonce(id: types::AccountId) -> DispatchResult {
        ensure!(Accounts::exists(id), "Account not found");

        let mut account = Accounts::get(id);
        account.nonce += 1;
        Accounts::insert(id, account);

        Ok(())
    }
    pub fn compute_balance(id: types::AccountId) -> Result<types::Balance, &'static str> {
        ensure!(Accounts::exists(id), "Account not found");
        let created_at = Accounts::get(id).created_at;
        let raw_bal = RawBalance::get(id);
        let confirmed_sum = Self::votes_cum(Self::term_number());
        let distributed_bal = confirmed_sum - Self::votes_cum(created_at);
        Ok(raw_bal + distributed_bal)
    }
}

/// tests for this module
#[cfg(test)]
mod tests {
    use super::*;

    use frame_support::{assert_ok, impl_outer_origin, parameter_types, weights::Weight};
    use sp_core::H256;
    use sp_runtime::{
        testing::Header,
        traits::{BlakeTwo256, IdentityLookup},
        Perbill,
    };

    impl_outer_origin! {
        pub enum Origin for Test {}
    }

    // For testing the module, we construct most of a mock runtime. This means
    // first constructing a configuration type (`Test`) which `impl`s each of the
    // configuration traits of modules we want to use.
    #[derive(Clone, Eq, PartialEq)]
    pub struct Test;
    parameter_types! {
        pub const BlockHashCount: u64 = 250;
        pub const MaximumBlockWeight: Weight = 1024;
        pub const MaximumBlockLength: u32 = 2 * 1024;
        pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
    }
    impl system::Trait for Test {
        type Origin = Origin;
        type Call = ();
        type Index = u64;
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
        type Header = Header;
        type Event = ();
        type BlockHashCount = BlockHashCount;
        type MaximumBlockWeight = MaximumBlockWeight;
        type MaximumBlockLength = MaximumBlockLength;
        type AvailableBlockRatio = AvailableBlockRatio;
        type Version = ();
    }
    impl Trait for Test {
        type Event = ();
    }
    type MynaChainModule = Module<Test>;

    // This function basically just builds a genesis storage key/value store according to
    // our desired mockup.
    fn new_test_ext() -> sp_io::TestExternalities {
        system::GenesisConfig::default()
            .build_storage::<Test>()
            .unwrap()
            .into()
    }

    #[test]
    fn it_works_for_default_value() {
        new_test_ext().execute_with(|| {});
    }
}
