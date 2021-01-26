//! A demonstration of an offchain worker that sends onchain callbacks


//通过上课和查文档，学习到有三种交易⽅法把计算结果写回链上：
// 1. 签名交易。
// 2. 不签名交易。
// 3. 不签名交易但有签名数据。
//
// 这次作业里，我采用"不签名交易但有签名数据"的方式。
// 本次作业的场景，是往链上写入dot的实时行情数据，此类数据更新频率在每秒若干条，
// 具有实时数据量大,且因为行情数据后续可能用于指导交易决策分析，套利，DEX聚合等defi合约场景，
// 对数据准确性高，需要一个"权威者"发布到链上。
// 结合场景，具体原因分析如下:
// 1) 签名交易.因为要支付打包费用，交易成本很高。虽然能满足"权威者发布"的身份背书的要求，
// 但是大数据量的实时数据，交易成本太高。所以不考虑该方式。
// 2) 不签名交易. 该方式无需交易成本，适应该场景的大量实时数据的情况。
// 但是，因为没有签名信息，所以，其他人可以同时发布重复和垃圾数据。无法验证哪些数据是"权威，准确"的行情数据。
// 3）  不签名交易但有签名数据。该方式无需交易成本，适应该场景的大量实时数据的情况。同时，因为有签名，
// 所以满足了验证写到链上的数据的"权威，准确"的需求。

//  终上所述，我采用第三种方式 ，即"签名交易但有签名数据"


#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod tests;

use core::{convert::TryInto, fmt};
use frame_support::{
	debug, decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult,
};
use parity_scale_codec::{Decode, Encode};

use frame_system::{
	self as system, ensure_none, ensure_signed,
	offchain::{
		AppCrypto, CreateSignedTransaction, SendSignedTransaction, SendUnsignedTransaction,
		SignedPayload, SigningTypes, Signer, SubmitTransaction,
	},
};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	RuntimeDebug,
	offchain as rt_offchain,
	offchain::{
		storage::StorageValueRef,
		storage_lock::{StorageLock, BlockAndTime},
	},
	transaction_validity::{
		InvalidTransaction, TransactionSource, TransactionValidity,
		ValidTransaction,
	},
};
use sp_std::{
	prelude::*, str,
	collections::vec_deque::VecDeque,
};

use serde::{Deserialize, Deserializer};

/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When an offchain worker is signing transactions it's going to request keys from type
/// `KeyTypeId` via the keystore to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"demo");
pub const NUM_VEC_LEN: usize = 10;
/// The type to sign and send transactions.
pub const UNSIGNED_TXS_PRIORITY: u64 = 100;

// We are fetching information from the github public API about organization`substrate-developer-hub`.
pub const HTTP_REMOTE_REQUEST: &str = "https://api.coincap.io/v2/assets/polkadot";

pub const FETCH_TIMEOUT_PERIOD: u64 = 3000;
// in milli-seconds
pub const LOCK_TIMEOUT_EXPIRATION: u64 = FETCH_TIMEOUT_PERIOD + 1000;
// in milli-seconds
pub const LOCK_BLOCK_EXPIRATION: u32 = 3;
// in block number
pub const PRICE_ACC: f32 = 1000.0;

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrapper.
/// We can utilize the supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// them with the pallet-specific identifier.
pub mod crypto {
	use crate::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::app_crypto::{app_crypto, sr25519};
	use sp_runtime::{
		traits::Verify,
		MultiSignature, MultiSigner,
	};

	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;

	// implemented for ocw-runtime
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}

	// implemented for mock runtime in test
	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
	for TestAuthId
	{
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct Payload<Public> {
	dotPrice: u32,
	public: Public,
}

impl<T: SigningTypes> SignedPayload<T> for Payload<T::Public> {
	fn public(&self) -> T::Public {
		self.public.clone()
	}
}

// ref: https://serde.rs/container-attrs.html#crate
#[allow(non_snake_case)]
#[derive(Deserialize, Encode, Decode, Clone, Default)]
struct DotRTPriceData {
	// Specify our own deserializing function to convert JSON string to vector of bytes
	#[serde(deserialize_with = "de_string_to_bytes")]
	priceVector: Vec<u8>,
}

#[allow(non_snake_case)]
#[derive(Deserialize, Encode, Decode, Clone, Default)]
struct DotRTPriceInfo {
	// Specify our own deserializing function to convert JSON string to vector of bytes
	data: DotRTPriceData,
	timestamp: u64,
}

pub fn de_string_to_bytes<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
	where
		D: Deserializer<'de>,
{
	let s: &str = Deserialize::deserialize(de)?;
	Ok(s.as_bytes().to_vec())
}

impl fmt::Debug for DotRTPriceInfo {
	// `fmt` converts the vector of bytes inside the struct back to string for
	//   more friendly display.
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"{{ dot price: {}, generated timestamp: {}}}",
			str::from_utf8(&self.data.priceVector).map_err(|_| fmt::Error)?,
			self.timestamp
		)
	}
}

/// This is the pallet's configuration trait
pub trait Trait: system::Trait + CreateSignedTransaction<Call<Self>> {
	/// The identifier type for an offchain worker.
	type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
	/// The overarching dispatch call type.
	type Call: From<Call<Self>>;
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_storage! {
	trait Store for Module<T: Trait> as Example {
		/// A vector of recently submitted numbers. Bounded by NUM_VEC_LEN
		Prices get(fn numbers): VecDeque<u32>;
	}
}

decl_event!(
	/// Events generated by the module.
	pub enum Event<T>
	where
		AccountId = <T as system::Trait>::AccountId,
	{
		/// Event generated when a new number is accepted to contribute to the average.
		NewPrice(Option<AccountId>, u32),
	}
);

decl_error! {
	pub enum Error for Module<T: Trait> {
		// Error returned when not sure which ocw function to executed
		UnknownOffchainMux,

		// Error returned when making signed transactions in off-chain worker
		NoLocalAcctForSigning,
		OffchainSignedTxError,

		// Error returned when making unsigned transactions in off-chain worker
		OffchainUnsignedTxError,

		// Error returned when making unsigned transactions with signed payloads in off-chain worker
		OffchainUnsignedTxSignedPayloadError,

		// Error returned when fetching github info
		HttpFetchingError,

		PriceParsedError,
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		fn deposit_event() = default;

		#[weight = 10000]
		pub fn submit_number_unsigned_with_signed_payload(origin, payload: Payload<T::Public>,
			_signature: T::Signature) -> DispatchResult
		{
			let _ = ensure_none(origin)?;
			// we don't need to verify the signature here because it has been verified in
			//   `validate_unsigned` function when sending out the unsigned tx.
			let Payload { price, public } = payload;
			debug::info!("submit_number_unsigned_with_signed_payload: ({}, {:?})", price, public);
			Self::append_or_replace_price(price);

			Self::deposit_event(RawEvent::NewPrice(None, price));
			Ok(())
		}

		fn offchain_worker(block_number: T::BlockNumber) {
			debug::info!("off-chain worker");
			match Self::fetch_github_info() {
				Ok(info) => {

					if let Err(err) = Self::offchain_unsigned_tx_signed_payload(info) {
						debug::error!(" offchain_worker offchain_unsigned_tx_signed_payload error: {:?}", err);
					}
				},
				Err(e) => {
					debug::error!("offchain_worker fetch_github_info error: {:?}", e);
				}
			}
		}
	}
}

impl<T: Trait> Module<T> {
	/// Append a new number to the tail of the list, removing an element from the head if reaching
	///   the bounded length.
	fn append_or_replace_price(price: u32) {
		Prices::mutate(|prices| {
			if prices.len() == NUM_VEC_LEN {
				let _ = prices.pop_front();
			}
			prices.push_back(price);
			debug::info!(" Prices vector: {:?}", prices);
		});
	}

	/// Check if we have fetched github info before. If yes, we can use the cached version
	///   stored in off-chain worker storage `storage`. If not, we fetch the remote info and
	///   write the info into the storage for future retrieval.
	fn fetch_github_info() -> Result<DotRTPriceInfo, Error<T>> {
		// Create a reference to Local Storage value.
		// Since the local storage is common for all offchain workers, it's a good practice
		// to prepend our entry with the pallet name.
		let s_info = StorageValueRef::persistent(b"offchain-demo::gh-info");

		// Local storage is persisted and shared between runs of the offchain workers,
		// offchain workers may run concurrently. We can use the `mutate` function to
		// write a storage entry in an atomic fashion.
		//
		// With a similar API as `StorageValue` with the variables `get`, `set`, `mutate`.
		// We will likely want to use `mutate` to access
		// the storage comprehensively.
		//
		// Ref: https://substrate.dev/rustdocs/v2.0.0/sp_runtime/offchain/storage/struct.StorageValueRef.html
		if let Some(Some(price_info)) = s_info.get::<DotRTPriceInfo>() {
			// gh-info has already been fetched. Return early.
			debug::info!("before price-info: {:?}", price_info);
		}

		// Since off-chain storage can be accessed by off-chain workers from multiple runs, it is important to lock
		//   it before doing heavy computations or write operations.
		// ref: https://substrate.dev/rustdocs/v2.0.0-rc3/sp_runtime/offchain/storage_lock/index.html
		//
		// There are four ways of defining a lock:
		//   1) `new` - lock with default time and block exipration
		//   2) `with_deadline` - lock with default block but custom time expiration
		//   3) `with_block_deadline` - lock with default time but custom block expiration
		//   4) `with_block_and_time_deadline` - lock with custom time and block expiration
		// Here we choose the most custom one for demonstration purpose.
		let mut lock = StorageLock::<BlockAndTime<Self>>::with_block_and_time_deadline(
			b"offchain-demo::lock", LOCK_BLOCK_EXPIRATION,
			rt_offchain::Duration::from_millis(LOCK_TIMEOUT_EXPIRATION),
		);

		// We try to acquire the lock here. If failed, we know the `fetch_n_parse` part inside is being
		//   executed by previous run of ocw, so the function just returns.
		// ref: https://substrate.dev/rustdocs/v2.0.0/sp_runtime/offchain/storage_lock/struct.StorageLock.html#method.try_lock

		if let Ok(_guard) = lock.try_lock() {
			match Self::fetch_n_parse() {
				Ok(price_info) => {
					s_info.set(&price_info);
					Ok(price_info)
				}
				Err(err) => {
					Err(err)
				}
			}
		}

	}

		/// Fetch from remote and deserialize the JSON to a struct
		fn fetch_n_parse() -> Result<DotRTPriceInfo, Error<T>> {
			let resp_bytes = Self::fetch_from_remote().map_err(|e| {
				debug::error!("fetch_from_remote error: {:?}", e);
				<Error<T>>::HttpFetchingError
			})?;

			let resp_str = str::from_utf8(&resp_bytes).map_err(|_| <Error<T>>::HttpFetchingError)?;
			// Print out our fetched JSON string
			debug::info!("{}", resp_str);

			// Deserializing JSON to struct, thanks to `serde` and `serde_derive`
			let price_info: DotRTPriceInfo =
				serde_json::from_str(&resp_str).map_err(|_| <Error<T>>::HttpFetchingError)?;
			Ok(price_info)
		}

		/// This function uses the `offchain::http` API to query the remote github information,
      ///   and returns the JSON response as vector of bytes.
		fn fetch_from_remote() -> Result<Vec<u8>, Error<T>> {
			debug::info!("sending request to: {}", HTTP_REMOTE_REQUEST);

			// Initiate an external HTTP GET request. This is using high-level wrappers from `sp_runtime`.
			let request = rt_offchain::http::Request::get(HTTP_REMOTE_REQUEST);

			// Keeping the offchain worker execution time reasonable, so limiting the call to be within 3s.
			let timeout = sp_io::offchain::timestamp()
				.add(rt_offchain::Duration::from_millis(FETCH_TIMEOUT_PERIOD));

			// For github API request, we also need to specify `user-agent` in http request header.
			//   See: https://developer.github.com/v3/#user-agent-required
			let pending = request
				.deadline(timeout) // Setting the timeout time
				.send() // Sending the request out by the host
				.map_err(|_| <Error<T>>::HttpFetchingError)?;

			// By default, the http request is async from the runtime perspective. So we are asking the
			//   runtime to wait here.
			// The returning value here is a `Result` of `Result`, so we are unwrapping it twice by two `?`
			//   ref: https://substrate.dev/rustdocs/v2.0.0/sp_runtime/offchain/http/struct.PendingRequest.html#method.try_wait
			let response = pending
				.try_wait(timeout)
				.map_err(|_| <Error<T>>::HttpFetchingError)?
				.map_err(|_| <Error<T>>::HttpFetchingError)?;

			if response.code != 200 {
				debug::error!("Unexpected http request status code: {}", response.code);
				return Err(<Error<T>>::HttpFetchingError);
			}

			// Next we fully read the response body and collect it to a vector of bytes.
			Ok(response.body().collect::<Vec<u8>>())
		}

		fn offchain_unsigned_tx_signed_payload(price_info: DotRTPriceInfo) -> Result<(), Error<T>> {
			// Retrieve the signer to sign the payload
			let signer = Signer::<T, T::AuthorityId>::any_account();

			let price = Self::parse_price_info(&price_info)?;

			// `send_unsigned_transaction` is returning a type of `Option<(Account<T>, Result<(), ()>)>`.
			//   Similar to `send_signed_transaction`, they account for:
			//   - `None`: no account is available for sending transaction
			//   - `Some((account, Ok(())))`: transaction is successfully sent
			//   - `Some((account, Err(())))`: error occured when sending the transaction
			if let Some((_, res)) = signer.send_unsigned_transaction(
				|acct| Payload { dotPrice: price, public: acct.public.clone() },
				Call::submit_number_unsigned_with_signed_payload,
			) {
				return res.map_err(|_| {
					debug::error!("Failed in offchain_unsigned_tx_signed_payload");
					<Error<T>>::OffchainUnsignedTxSignedPayloadError
				});
			}

			// The case of `None`: no account is available for sending
			debug::error!("No local account available");
			Err(<Error<T>>::NoLocalAcctForSigning)
		}

		fn parse_price_info(price_info: &DotRTPriceInfo) -> Result<u32, Error<T>> {
			let price_str = str::from_utf8(&price_info.data.priceVector).map_err(|_| <Error<T>>::PriceParsedError)?;
			let currentPrice: f32 = price_str.parse().map_err(|_| <Error<T>>::PriceParsedError)?;
			Ok((currentPrice * PRICE_ACC) as u32)
		}
	}

	impl< T: Trait > frame_support::unsigned::ValidateUnsigned for Module < T > {
	type Call = Call < T >;

	fn validate_unsigned(_source: TransactionSource, call: & Self::Call) -> TransactionValidity {
	let valid_tx = | provide | ValidTransaction::with_tag_prefix("ocw-demo")
	.priority(UNSIGNED_TXS_PRIORITY)
	.and_provides([ & provide])
	.longevity(3)
	.propagate(true)
	.build();

	match call {
	Call::submit_number_unsigned_with_signed_payload( ref payload, ref signature) => {
	if ! SignedPayload::< T >::verify::< T::AuthorityId > (payload, signature.clone()) {
	return InvalidTransaction::BadProof.into();
	}
	valid_tx(b"submit_number_unsigned_with_signed_payload".to_vec())
	},
	_ => InvalidTransaction::Call.into(),
	}
	}
	}

	impl < T: Trait > rt_offchain::storage_lock::BlockNumberProvider for Module < T > {
	type BlockNumber = T::BlockNumber;
	fn current_block_number() -> Self::BlockNumber {
	< frame_system::Module < T > >::block_number()
	}
	}
