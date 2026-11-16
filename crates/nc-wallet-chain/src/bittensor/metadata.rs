//! The runtime's metadata, read just far enough to check that the signing
//! core's encoder still matches the runtime it is about to sign for.
//!
//! The core writes a Bittensor transfer from fixed assumptions: which pallet
//! and call index a transfer has, which transaction extensions follow the
//! signature and what each adds to the extrinsic and to the signed payload,
//! and how an account's balance is laid out. A runtime upgrade can change any
//! of them. Most upgrades change none (Bittensor ships one every week or two),
//! so rather than stop at every new spec version, each new runtime's metadata
//! is read and every assumption checked against it. A runtime that fails is
//! **not signed for**: nothing is guessed.
//!
//! The metadata is the version 14 form `state_getMetadata` returns. It is read
//! by a small decoder of its own (the registry of types, the pallets, the
//! extrinsic format) instead of the general SCALE libraries, which would add
//! a good part of a megabyte to the WebAssembly. Types are compared by shape
//! rather than by name, looking through the newtypes Subtensor wraps its
//! balances and extensions in, so that renaming a type does not stop transfers
//! and changing its encoding does.
//!
//! Events are not read: a wallet only sends.

/// The runtime this encoder was written for.
pub const SPEC_NAME: &str = "node-subtensor";
/// The extrinsic format the encoder writes.
const EXTRINSIC_VERSION: u8 = 4;
/// `Balances`' index and its calls' indices.
const BALANCES: u8 = 5;
const TRANSFER_KEEP_ALIVE: u8 = 3;
/// The runtime APIs the fee quote and the refusal check call, and their versions.
const TAGGED_TRANSACTION_QUEUE: [u8; 8] = [0xd2, 0xbc, 0x98, 0x97, 0xee, 0xd0, 0x8f, 0x15];
const TAGGED_TRANSACTION_QUEUE_VERSION: u32 = 3;
const TRANSACTION_PAYMENT_API: [u8; 8] = [0x37, 0xc8, 0xbb, 0x13, 0x50, 0xa9, 0xa2, 0xa8];
const TRANSACTION_PAYMENT_API_VERSION: u32 = 4;

/// What a type must encode as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Nothing at all: an empty struct or tuple.
    Nothing,
    /// A `u32`.
    U32,
    /// Thirty-two bytes.
    Hash,
    /// `sp_runtime`'s `Era`: a zero byte for immortal, or two bytes.
    Era,
    /// A compact `u32`.
    CompactU32,
    /// A compact `u64`.
    CompactU64,
    /// `CheckMetadataHash`'s mode: a byte, zero for disabled.
    MetadataHashMode,
    /// An optional thirty-two-byte hash: a zero byte for none.
    OptionHash,
}

/// The transaction extensions Finney's runtime lists, in order, with what each
/// adds to the extrinsic and what to the signed payload. The encoder writes
/// exactly this; any other list stops transfers.
const EXTENSIONS: [(&str, Shape, Shape); 13] = [
    ("CheckNonZeroSender", Shape::Nothing, Shape::Nothing),
    ("CheckSpecVersion", Shape::Nothing, Shape::U32),
    ("CheckTxVersion", Shape::Nothing, Shape::U32),
    ("CheckGenesis", Shape::Nothing, Shape::Hash),
    ("CheckMortality", Shape::Era, Shape::Hash),
    ("CheckNonce", Shape::CompactU32, Shape::Nothing),
    ("CheckWeight", Shape::Nothing, Shape::Nothing),
    ("ChargeTransactionPayment", Shape::CompactU64, Shape::Nothing),
    ("SudoTransactionExtension", Shape::Nothing, Shape::Nothing),
    ("CheckShieldedTxValidity", Shape::Nothing, Shape::Nothing),
    ("SubtensorTransactionExtension", Shape::Nothing, Shape::Nothing),
    ("DrandPriority", Shape::Nothing, Shape::Nothing),
    ("CheckMetadataHash", Shape::MetadataHashMode, Shape::OptionHash),
];

/// What a runtime is, once it has passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runtime {
    /// Its spec version, which every signature covers.
    pub spec_version: u32,
    /// Its transaction version, which every signature covers.
    pub transaction_version: u32,
    /// The least an account may hold, in rao.
    pub existential_deposit: u64,
}

/// Why metadata is not to be signed for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault(pub String);

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---- a reader of SCALE -------------------------------------------------------

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    /// A compact integer that must fit a `u32` (lengths and type ids).
    fn compact(&mut self) -> Option<u32> {
        u32::try_from(compact_u64(&mut self.0)?).ok()
    }

    /// A count that cannot be more than the bytes left (a list of anything
    /// takes at least a byte per item), so a lie cannot allocate.
    fn count(&mut self) -> Option<usize> {
        let n = usize::try_from(self.compact()?).ok()?;
        (n <= self.0.len()).then_some(n)
    }

    fn string(&mut self) -> Option<String> {
        let n = self.count()?;
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }

    fn skip_strings(&mut self) -> Option<()> {
        for _ in 0..self.count()? {
            self.string()?;
        }
        Some(())
    }

    fn option(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
}

/// SCALE's compact integer: the low two bits of the first byte say how many
/// bytes follow, and a big-integer mode carries a length.
pub(crate) fn compact_u64(input: &mut &[u8]) -> Option<u64> {
    let (&first, rest) = input.split_first()?;
    match first & 0b11 {
        0 => {
            *input = rest;
            Some(u64::from(first >> 2))
        }
        1 => {
            let bytes = rest.first()?;
            *input = &rest[1..];
            Some(u64::from(u16::from_le_bytes([first, *bytes]) >> 2))
        }
        2 => {
            let tail = rest.get(..3)?;
            *input = &rest[3..];
            Some(u64::from(u32::from_le_bytes([first, tail[0], tail[1], tail[2]]) >> 2))
        }
        _ => {
            let width = usize::from(first >> 2) + 4;
            if width > 8 {
                return None;
            }
            let tail = rest.get(..width)?;
            *input = &rest[width..];
            let mut value = 0_u64;
            for (shift, byte) in tail.iter().enumerate() {
                value |= u64::from(*byte) << (8 * shift);
            }
            Some(value)
        }
    }
}

// ---- the registry ------------------------------------------------------------

#[derive(Debug, Clone)]
struct Field {
    name: Option<String>,
    ty: u32,
}

#[derive(Debug, Clone)]
struct Variant {
    name: String,
    index: u8,
    fields: Vec<Field>,
}

#[derive(Debug, Clone)]
enum Def {
    Composite(Vec<Field>),
    Variant(Vec<Variant>),
    Sequence,
    Array { len: u32, ty: u32 },
    Tuple(Vec<u32>),
    Primitive(u8),
    Compact(u32),
    BitSequence,
}

#[derive(Debug, Clone)]
struct Type {
    params: Vec<(String, Option<u32>)>,
    def: Def,
}

const U8: u8 = 3;
const U32: u8 = 5;
const U64: u8 = 6;
const U128: u8 = 7;

fn read_fields(r: &mut Reader<'_>) -> Option<Vec<Field>> {
    let mut fields = Vec::new();
    for _ in 0..r.count()? {
        let name = if r.option()? { Some(r.string()?) } else { None };
        let ty = r.compact()?;
        if r.option()? {
            r.string()?; // type_name
        }
        r.skip_strings()?; // docs
        fields.push(Field { name, ty });
    }
    Some(fields)
}

fn read_type(r: &mut Reader<'_>) -> Option<Type> {
    r.skip_strings()?; // path
    let mut params = Vec::new();
    for _ in 0..r.count()? {
        let name = r.string()?;
        let ty = if r.option()? { Some(r.compact()?) } else { None };
        params.push((name, ty));
    }
    let def = match r.u8()? {
        0 => Def::Composite(read_fields(r)?),
        1 => {
            let mut variants = Vec::new();
            for _ in 0..r.count()? {
                let name = r.string()?;
                let fields = read_fields(r)?;
                let index = r.u8()?;
                r.skip_strings()?; // docs
                variants.push(Variant { name, index, fields });
            }
            Def::Variant(variants)
        }
        2 => {
            r.compact()?;
            Def::Sequence
        }
        3 => {
            let len = r.u32()?;
            Def::Array { len, ty: r.compact()? }
        }
        4 => {
            let mut items = Vec::new();
            for _ in 0..r.count()? {
                items.push(r.compact()?);
            }
            Def::Tuple(items)
        }
        5 => Def::Primitive(r.u8()?),
        6 => Def::Compact(r.compact()?),
        7 => {
            r.compact()?;
            r.compact()?;
            Def::BitSequence
        }
        _ => return None,
    };
    r.skip_strings()?; // docs
    Some(Type { params, def })
}

struct Registry(Vec<Type>);

impl Registry {
    fn def(&self, id: u32) -> Option<&Def> {
        self.0.get(usize::try_from(id).ok()?).map(|ty| &ty.def)
    }

    /// The type a chain of one-field structs and one-element tuples wraps:
    /// `TaoBalance(u64)` is a `u64`, `AccountId32([u8; 32])` thirty-two bytes.
    fn unwrap(&self, mut id: u32) -> u32 {
        for _ in 0..16 {
            match self.def(id) {
                Some(Def::Composite(fields)) if fields.len() == 1 => id = fields[0].ty,
                Some(Def::Tuple(items)) if items.len() == 1 => id = items[0],
                _ => break,
            }
        }
        id
    }

    fn is_nothing(&self, id: u32, depth: u8) -> bool {
        let Some(depth) = depth.checked_sub(1) else { return false };
        match self.def(id) {
            Some(Def::Composite(fields)) => fields.iter().all(|f| self.is_nothing(f.ty, depth)),
            Some(Def::Tuple(items)) => items.iter().all(|i| self.is_nothing(*i, depth)),
            Some(Def::Array { len, ty }) => *len == 0 || self.is_nothing(*ty, depth),
            _ => false,
        }
    }

    fn is_primitive(&self, id: u32, primitive: u8) -> bool {
        matches!(self.def(self.unwrap(id)), Some(Def::Primitive(found)) if *found == primitive)
    }

    fn is_bytes(&self, id: u32, length: u32) -> bool {
        matches!(
            self.def(self.unwrap(id)),
            Some(Def::Array { len, ty }) if *len == length && self.is_primitive(*ty, U8)
        )
    }

    fn is_compact(&self, id: u32, primitive: u8) -> bool {
        matches!(
            self.def(self.unwrap(id)),
            Some(Def::Compact(inner)) if self.is_primitive(*inner, primitive)
        )
    }

    fn variants(&self, id: u32) -> Option<&[Variant]> {
        match self.def(self.unwrap(id)) {
            Some(Def::Variant(variants)) => Some(variants),
            _ => None,
        }
    }

    fn fields(&self, id: u32) -> Option<&[Field]> {
        match self.def(id) {
            Some(Def::Composite(fields)) => Some(fields),
            _ => None,
        }
    }

    /// The single field of variant `index` of an enum, if it has exactly one.
    fn only_field(&self, id: u32, index: u8, name: &str) -> Option<u32> {
        let variant = self.variants(id)?.iter().find(|v| v.index == index)?;
        match variant.fields.as_slice() {
            [field] if variant.name == name => Some(field.ty),
            _ => None,
        }
    }

    fn fits(&self, id: u32, shape: Shape) -> bool {
        match shape {
            Shape::Nothing => self.is_nothing(id, 16),
            Shape::U32 => self.is_primitive(id, U32),
            Shape::Hash => self.is_bytes(id, 32),
            Shape::Era => self.variants(id).is_some_and(|variants| {
                variants.len() == 256
                    && variants.iter().all(|variant| match variant.index {
                        0 => variant.name == "Immortal" && variant.fields.is_empty(),
                        _ => match variant.fields.as_slice() {
                            [field] => self.is_primitive(field.ty, U8),
                            _ => false,
                        },
                    })
            }),
            Shape::CompactU32 => self.is_compact(id, U32),
            Shape::CompactU64 => self.is_compact(id, U64),
            Shape::MetadataHashMode => self.variants(id).is_some_and(|variants| {
                variants.iter().any(|v| v.index == 0 && v.name == "Disabled" && v.fields.is_empty())
            }),
            Shape::OptionHash => self.variants(id).is_some_and(|variants| {
                let none = variants
                    .iter()
                    .any(|v| v.index == 0 && v.name == "None" && v.fields.is_empty());
                none && self.only_field(id, 1, "Some").is_some_and(|some| self.is_bytes(some, 32))
            }),
        }
    }

    /// A `MultiAddress` whose variant 0, `Id`, holds a 32-byte account.
    fn is_address(&self, id: u32) -> bool {
        self.only_field(id, 0, "Id").is_some_and(|account| self.is_bytes(account, 32))
    }

    /// Whether a struct's fields are exactly these names, in this order, each
    /// passing its test.
    fn has_fields(&self, id: u32, expected: &[(&str, &dyn Fn(u32) -> bool)]) -> bool {
        self.fields(id).is_some_and(|fields| {
            fields.len() == expected.len()
                && fields.iter().zip(expected).all(|(field, (name, test))| {
                    field.name.as_deref() == Some(*name) && test(field.ty)
                })
        })
    }
}

// ---- the pallets and the extrinsic -------------------------------------------

struct Pallet {
    name: String,
    /// `System.Account`'s storage, when this pallet has storage entries read.
    account: Option<AccountStorage>,
    calls: Option<u32>,
    constants: Vec<(String, u32, Vec<u8>)>,
    index: u8,
    storage_prefix: Option<String>,
}

struct AccountStorage {
    hashers: Vec<u8>,
    key: u32,
    value: u32,
}

struct Extension {
    identifier: String,
    ty: u32,
    additional_signed: u32,
}

struct Metadata {
    registry: Registry,
    pallets: Vec<Pallet>,
    extrinsic_ty: u32,
    extrinsic_version: u8,
    extensions: Vec<Extension>,
}

fn read_pallet(r: &mut Reader<'_>) -> Option<Pallet> {
    let name = r.string()?;
    let mut account = None;
    let mut storage_prefix = None;
    if r.option()? {
        let prefix = r.string()?;
        for _ in 0..r.count()? {
            let entry = r.string()?;
            r.u8()?; // modifier
            let (hashers, key, value, plain) = match r.u8()? {
                0 => (Vec::new(), 0, r.compact()?, true),
                1 => {
                    let mut hashers = Vec::new();
                    for _ in 0..r.count()? {
                        hashers.push(r.u8()?);
                    }
                    let key = r.compact()?;
                    (hashers, key, r.compact()?, false)
                }
                _ => return None,
            };
            let n = r.count()?;
            r.take(n)?; // default
            r.skip_strings()?; // docs
            if name == "System" && entry == "Account" && !plain {
                account = Some(AccountStorage { hashers, key, value });
            }
        }
        storage_prefix = Some(prefix);
    }
    let calls = if r.option()? { Some(r.compact()?) } else { None };
    if r.option()? {
        r.compact()?; // events
    }
    let mut constants = Vec::new();
    for _ in 0..r.count()? {
        let constant = r.string()?;
        let ty = r.compact()?;
        let n = r.count()?;
        let value = r.take(n)?.to_vec();
        r.skip_strings()?; // docs
        constants.push((constant, ty, value));
    }
    if r.option()? {
        r.compact()?; // errors
    }
    let index = r.u8()?;
    Some(Pallet { name, account, calls, constants, index, storage_prefix })
}

fn read_metadata(bytes: &[u8]) -> Option<Metadata> {
    let mut r = Reader(bytes);
    if r.take(4)? != b"meta" || r.u8()? != 14 {
        return None;
    }
    let mut types: Vec<Type> = Vec::new();
    for expected in 0..r.count()? {
        let id = r.compact()?;
        if usize::try_from(id).ok()? != expected {
            return None;
        }
        types.push(read_type(&mut r)?);
    }
    let mut pallets = Vec::new();
    for _ in 0..r.count()? {
        pallets.push(read_pallet(&mut r)?);
    }
    let extrinsic_ty = r.compact()?;
    let extrinsic_version = r.u8()?;
    let mut extensions = Vec::new();
    for _ in 0..r.count()? {
        extensions.push(Extension {
            identifier: r.string()?,
            ty: r.compact()?,
            additional_signed: r.compact()?,
        });
    }
    Some(Metadata {
        registry: Registry(types),
        pallets,
        extrinsic_ty,
        extrinsic_version,
        extensions,
    })
}

/// `sp_version::RuntimeVersion`, as `System.Version` holds it: the name, the
/// versions, and the runtime APIs.
fn read_version(bytes: &[u8]) -> Option<(String, u32, u32, Vec<([u8; 8], u32)>)> {
    let mut r = Reader(bytes);
    let spec_name = r.string()?;
    r.string()?; // impl_name
    r.u32()?; // authoring_version
    let spec_version = r.u32()?;
    r.u32()?; // impl_version
    let mut apis = Vec::new();
    for _ in 0..r.count()? {
        let id: [u8; 8] = r.take(8)?.try_into().ok()?;
        apis.push((id, r.u32()?));
    }
    let transaction_version = r.u32()?;
    r.u8()?; // state_version
    r.0.is_empty().then_some((spec_name, spec_version, transaction_version, apis))
}

/// Reads a runtime's metadata, as `state_getMetadata` returns it, and checks
/// every assumption the encoder makes against it.
pub fn check(bytes: &[u8]) -> Result<Runtime, Fault> {
    let fault = |what: &str| Fault(what.to_owned());
    let metadata = read_metadata(bytes).ok_or_else(|| fault("the metadata does not read"))?;
    let registry = &metadata.registry;
    let pallet = |name: &str| metadata.pallets.iter().find(|p| p.name == name);

    let system = pallet("System").ok_or_else(|| fault("no System pallet"))?;
    let balances = pallet("Balances").ok_or_else(|| fault("no Balances pallet"))?;
    let version = system
        .constants
        .iter()
        .find(|c| c.0 == "Version")
        .ok_or_else(|| fault("no System.Version"))?;
    let (spec_name, spec_version, transaction_version, apis) =
        read_version(&version.2).ok_or_else(|| fault("System.Version does not read"))?;
    let deposit = balances
        .constants
        .iter()
        .find(|c| c.0 == "ExistentialDeposit")
        .ok_or_else(|| fault("no Balances.ExistentialDeposit"))?;
    if !registry.is_primitive(deposit.1, U64) {
        return Err(fault("the existential deposit is not a u64"));
    }
    let existential_deposit = <[u8; 8]>::try_from(deposit.2.as_slice())
        .map(u64::from_le_bytes)
        .map_err(|_| fault("the existential deposit is not eight bytes"))?;

    let mut problems: Vec<String> = Vec::new();
    if spec_name != SPEC_NAME {
        problems.push(format!("the runtime is {spec_name}, not {SPEC_NAME}"));
    }
    for (id, name, expected) in [
        (TAGGED_TRANSACTION_QUEUE, "TaggedTransactionQueue", TAGGED_TRANSACTION_QUEUE_VERSION),
        (TRANSACTION_PAYMENT_API, "TransactionPaymentApi", TRANSACTION_PAYMENT_API_VERSION),
    ] {
        match apis.iter().find(|(api, _)| *api == id) {
            Some((_, version)) if *version == expected => {}
            Some((_, version)) => {
                problems.push(format!("{name} is version {version}, not {expected}"));
            }
            None => problems.push(format!("the runtime offers no {name}")),
        }
    }
    check_extrinsic(&metadata, &mut problems);
    check_balances(registry, balances, &mut problems);
    check_system(registry, system, &mut problems);

    if problems.is_empty() {
        Ok(Runtime { spec_version, transaction_version, existential_deposit })
    } else {
        Err(Fault(problems.join("; ")))
    }
}

fn check_extrinsic(metadata: &Metadata, problems: &mut Vec<String>) {
    let registry = &metadata.registry;
    if metadata.extrinsic_version != EXTRINSIC_VERSION {
        problems.push(format!(
            "extrinsics are format {}, not {EXTRINSIC_VERSION}",
            metadata.extrinsic_version
        ));
    }
    let parameter = |name: &str| {
        registry
            .0
            .get(usize::try_from(metadata.extrinsic_ty).ok()?)?
            .params
            .iter()
            .find(|(param, _)| param == name)
            .and_then(|(_, ty)| *ty)
    };
    if !parameter("Address").is_some_and(|address| registry.is_address(address)) {
        problems.push("a sender is not a MultiAddress::Id of 32 bytes".to_owned());
    }
    // Both variants the encoder writes, whichever scheme the sender's key is.
    let signature = parameter("Signature");
    for (index, name) in [(0, "Ed25519"), (1, "Sr25519")] {
        if !signature.is_some_and(|s| {
            registry.only_field(s, index, name).is_some_and(|b| registry.is_bytes(b, 64))
        }) {
            problems.push(format!("a signature's variant {index} is not a 64-byte {name}"));
        }
    }
    let balances_calls =
        metadata.pallets.iter().find(|p| p.name == "Balances").and_then(|p| p.calls);
    if !parameter("Call").is_some_and(|call| {
        balances_calls.is_some_and(|b| registry.only_field(call, BALANCES, "Balances") == Some(b))
    }) {
        problems.push(format!("call variant {BALANCES} is not Balances"));
    }

    let listed: Vec<&str> = metadata.extensions.iter().map(|e| e.identifier.as_str()).collect();
    let expected: Vec<&str> = EXTENSIONS.iter().map(|(name, _, _)| *name).collect();
    if listed != expected {
        problems.push(format!("the transaction extensions are {listed:?}, not {expected:?}"));
        return;
    }
    for (extension, (name, explicit, implicit)) in metadata.extensions.iter().zip(EXTENSIONS) {
        if !registry.fits(extension.ty, explicit) {
            problems.push(format!("{name} does not add {explicit:?} to the extrinsic"));
        }
        if !registry.fits(extension.additional_signed, implicit) {
            problems.push(format!("{name} does not add {implicit:?} to the signed payload"));
        }
    }
}

/// Balances: its index, and `transfer_keep_alive`'s index and arguments.
fn check_balances(registry: &Registry, balances: &Pallet, problems: &mut Vec<String>) {
    if balances.index != BALANCES {
        problems.push(format!("Balances is pallet {}, not {BALANCES}", balances.index));
    }
    let Some(calls) = balances.calls.and_then(|ty| registry.variants(ty)) else {
        problems.push("Balances has no calls".to_owned());
        return;
    };
    let Some(call) = calls.iter().find(|call| call.name == "transfer_keep_alive") else {
        problems.push("Balances has no transfer_keep_alive".to_owned());
        return;
    };
    if call.index != TRANSFER_KEEP_ALIVE {
        problems.push(format!(
            "Balances.transfer_keep_alive is call {}, not {TRANSFER_KEEP_ALIVE}",
            call.index
        ));
    }
    let fits = call.fields.len() == 2
        && call.fields[0].name.as_deref() == Some("dest")
        && registry.is_address(call.fields[0].ty)
        && call.fields[1].name.as_deref() == Some("value")
        && registry.is_compact(call.fields[1].ty, U64);
    if !fits {
        problems.push(
            "Balances.transfer_keep_alive does not take a dest and a compact u64 value".to_owned(),
        );
    }
}

/// `System.Account`: where it lives, how it is keyed, and its layout.
fn check_system(registry: &Registry, system: &Pallet, problems: &mut Vec<String>) {
    // The storage keys in `bittensor` are hashes of these names.
    if system.storage_prefix.as_deref() != Some("System") {
        problems.push("System's storage is not under System".to_owned());
    }
    let Some(account) = &system.account else {
        problems.push("no System.Account map".to_owned());
        return;
    };
    // 2 is Blake2_128Concat.
    if account.hashers != [2] {
        problems.push(format!("System.Account is keyed by {:?}", account.hashers));
    }
    if !registry.is_bytes(account.key, 32) {
        problems.push("System.Account is not keyed by a 32-byte account".to_owned());
    }
    let u32_field = |id: u32| registry.is_primitive(id, U32);
    let u64_field = |id: u32| registry.is_primitive(id, U64);
    let u128_field = |id: u32| registry.is_primitive(id, U128);
    let data = |id: u32| {
        registry.has_fields(
            id,
            &[
                ("free", &u64_field),
                ("reserved", &u64_field),
                ("frozen", &u64_field),
                ("flags", &u128_field),
            ],
        )
    };
    let laid_out = registry.has_fields(
        account.value,
        &[
            ("nonce", &u32_field),
            ("consumers", &u32_field),
            ("providers", &u32_field),
            ("sufficients", &u32_field),
            ("data", &data),
        ],
    );
    if !laid_out {
        problems.push(
            "AccountInfo is not four u32s and AccountData of three u64s and a u128".to_owned(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINNEY_470: &[u8] = include_bytes!("../../tests/fixtures/finney-470.metadata");

    #[test]
    fn the_recorded_finney_runtime_passes_every_check() {
        let runtime = check(FINNEY_470).unwrap();
        assert_eq!(runtime.spec_version, 470);
        assert_eq!(runtime.transaction_version, 1);
        assert_eq!(runtime.existential_deposit, 500);
    }

    #[test]
    fn metadata_that_is_cut_short_or_not_metadata_is_refused() {
        assert!(check(&FINNEY_470[..FINNEY_470.len() / 2]).is_err());
        assert!(check(&[]).is_err());
        assert!(check(b"nope, not metadata at all").is_err());
        let mut wrong_version = FINNEY_470.to_vec();
        wrong_version[4] = 15;
        assert!(check(&wrong_version).is_err());
    }

    #[test]
    fn a_runtime_that_moves_the_transfer_call_is_not_signed_for() {
        let mut broken = FINNEY_470.to_vec();
        // Rename the call so that it cannot be found.
        let name_at = FINNEY_470
            .windows(b"transfer_keep_alive".len())
            .position(|w| w == b"transfer_keep_alive")
            .unwrap();
        broken[name_at] = b'x';
        let fault = check(&broken).unwrap_err();
        assert!(fault.0.contains("transfer_keep_alive"), "{fault}");
    }

    #[test]
    fn a_renamed_transaction_extension_is_not_signed_for() {
        let mut broken = FINNEY_470.to_vec();
        let at = FINNEY_470
            .windows(b"CheckMortality".len())
            .rposition(|w| w == b"CheckMortality")
            .unwrap();
        broken[at] = b'X';
        let fault = check(&broken).unwrap_err();
        assert!(fault.0.contains("transaction extensions"), "{fault}");
    }

    #[test]
    fn compact_integers_read_in_every_mode() {
        let read = |bytes: &[u8]| compact_u64(&mut &bytes[..]);
        assert_eq!(read(&[0x00]), Some(0));
        assert_eq!(read(&[0xfc]), Some(63));
        assert_eq!(read(&[0x01, 0x01]), Some(64));
        assert_eq!(read(&[0xfd, 0xff]), Some(16_383));
        assert_eq!(read(&[0x02, 0x00, 0x01, 0x00]), Some(16_384));
        assert_eq!(read(&[0x07, 0x00, 0x00, 0x00, 0x00, 0x01]), Some(1 << 32));
        assert_eq!(read(&[]), None);
        assert_eq!(read(&[0x02, 0x00]), None);
    }
}
