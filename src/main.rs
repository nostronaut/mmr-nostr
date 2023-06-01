use tungstenite::{connect, stream::MaybeTlsStream, Message as WsMessage, WebSocket};

use cloud_mmr::{
    self,
    hash::{DefaultHashable, Hash},
    merkle_proof::MerkleProof,
    pmmr::{ReadablePMMR, VecBackend, PMMR},
    ser::{PMMRable, Readable, Reader, Writeable, Writer},
};

use bitcoin_hashes::sha256::Hash as Sha256Hash;
use bitcoin_hashes::Hash as BitcoinHash;

use nostr::prelude::*;
use std::{collections::HashMap, net::TcpStream};

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

#[derive(Debug)]
enum Error {
    /// Event doesn't contain MMR tag
    MmrTagMissing,
    /// EventId already present in MMR
    EventAlreadyInMmr,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MmrTagMissing => write!(f, "Event doesn't contain MMR tag"),
            Self::EventAlreadyInMmr => write!(f, "EventId already present in MMR"),
        }
    }
}

#[derive(Eq, PartialEq)]
struct MmrTag {
    prev_event_id: Sha256Hash,
    prev_mmr_root: Sha256Hash,
    prev_event_pos: i64,
}

impl std::error::Error for Error {}

impl TryFrom<&nostr::Event> for MmrTag {
    type Error = Error;
    fn try_from(event: &nostr::Event) -> std::result::Result<Self, Self::Error> {
        event
            .tags
            .iter()
            .find_map(|tag| match tag {
                Tag::Mmr {
                    prev_event_id,
                    prev_mmr_root,
                    prev_event_pos,
                } => Some(MmrTag {
                    prev_event_id: *prev_event_id,
                    prev_mmr_root: *prev_mmr_root,
                    prev_event_pos: *prev_event_pos,
                }),
                _ => None,
            })
            .ok_or_else(|| Error::MmrTagMissing)
    }
}

struct Mmr<'a> {
    mmr: PMMR<'a, EventId, VecBackend<EventId>>,
    node_pos: HashMap<EventId, u64>,
}

impl<'a> Mmr<'a> {
    fn new(backend: &'a mut VecBackend<EventId>) -> Self {
        Mmr {
            mmr: PMMR::<EventId, VecBackend<EventId>>::new(backend),
            node_pos: Default::default(),
        }
    }
    fn new_event(&mut self, msg: &str, keys: &Keys) -> Result<Event> {
        let event = self.mmr_event(msg, keys)?;
        self.push((&event.id).into())?;
        Ok(event)
    }

    fn mmr_event(&self, msg: &str, keys: &Keys) -> Result<Event> {
        let builder = EventBuilder::new_text_note(msg, &[]);
        let event: Event = builder.to_mmr_event(
            keys,
            self.last_event_id(),
            self.mmr_root().unwrap(),
            self.last_event_pos()
                .and_then(|pos| pos.try_into().ok())
                .unwrap_or(-1),
        )?;
        event.verify()?;
        println!("Verified {:#?}", event);
        Ok(event)
    }

    fn is_event(event: &nostr::Event) -> bool {
        event.tags.iter().any(|tag| {
            matches!(tag, Tag::Mmr { .. }) || matches!(tag, Tag::Generic(TagKind::Mmr, ..))
        })
    }

    fn push(&mut self, event_id: EventId) -> Result<MerkleProof> {
        if self.node_pos.contains_key(&event_id) {
            return Err(Box::new(Error::EventAlreadyInMmr));
        }
        let leaf_pos = self.mmr.push(&event_id)?;
        self.mmr.validate()?;
        println!("Verified pmmr");
        // log_mmr_update(&self.pmmr);
        self.node_pos.insert(event_id, leaf_pos);
        let proof = self.merkle_proof(&event_id).unwrap();
        Ok(proof)
    }

    fn last_mmr_tag(&self) -> MmrTag {
        MmrTag {
            prev_event_id: self.last_event_id(),
            prev_mmr_root: self.mmr_root().unwrap_or_else(Sha256Hash::all_zeros),
            prev_event_pos: self
                .last_event_pos()
                .and_then(|pos| pos.try_into().ok())
                .unwrap_or(-1),
        }
    }

    // TODO: return should be Result<MerkleProof>
    fn merkle_proof(&self, event_id: &EventId) -> Option<MerkleProof> {
        self.node_pos
            .get(&event_id)
            .and_then(|node_pos| self.mmr.merkle_proof(*node_pos).ok())
    }

    fn is_mmr_member(&self, event_id: &EventId) -> bool {
        self.node_pos.get(event_id).is_some()
    }

    fn log_mmr_update(&self, pmmr: &Mmr) {
        println!("mmr updated");
        println!("mmr_root: {:#?}", self.mmr_root().unwrap());
        println!("event_id_hash: {:#?}", &self.last_event_hash());
        println!("event_id: {:#?}", &self.last_event_id());
    }

    // TODO: doesnt belong here
    fn verify_merkle_proof(proof: MerkleProof, root: Hash, elem: &EventId, node_pos: u64) -> bool {
        if let Ok(_) = proof.verify(root, elem, node_pos) {
            true
        } else {
            false
        }
    }

    fn mmr_root(&self) -> Option<Sha256Hash> {
        self.mmr.root().ok().as_ref().and_then(Self::convert_hash)
    }

    fn convert_hash(hash: &Hash) -> Option<Sha256Hash> {
        Sha256Hash::from_slice(hash.as_ref()).ok()
    }

    fn last_event_pos(&self) -> Option<u64> {
        self.mmr.leaf_pos_iter().last()
    }

    fn last_event_id(&self) -> Sha256Hash {
        self.last_event_pos()
            .and_then(|ix| self.mmr.get_data(ix))
            .map(|id| id.0)
            .unwrap_or_else(Sha256Hash::all_zeros)
    }

    fn last_event_hash(&self) -> Sha256Hash {
        self.last_event_pos()
            .and_then(|ix| self.mmr.get_hash(ix))
            .as_ref()
            .and_then(Self::convert_hash)
            .unwrap_or_else(Sha256Hash::all_zeros)
    }

    fn is_next(&self, prev_event_pos: i64) -> bool {
        let last_event_pos = self
            .last_event_pos()
            .and_then(|pos| pos.try_into().ok())
            .unwrap_or(-1);
        println!("last {}, prev {}", &last_event_pos, &prev_event_pos);
        prev_event_pos == last_event_pos
    }
}

struct Runtime {
    keys: Keys,
    sockets: Vec<Socket>,
    subscriptions: Vec<SubscriptionId>,
}

impl Runtime {
    fn socket(&mut self) -> Vec<&mut Socket> {
        self.sockets.iter_mut().collect()
    }

    fn connect(&mut self, ws_endpoint: &str) -> Result<()> {
        let (socket, _response) = connect(Url::parse(ws_endpoint)?)?;
        self.sockets.push(socket);
        Ok(())
    }

    fn subscribe(&mut self, pk: XOnlyPublicKey) -> Result<()> {
        let id = SubscriptionId::generate();
        let sub = ClientMessage::new_req(
            id.clone(),
            vec![Filter::new().author(pk.to_string()).kind(Kind::TextNote)],
        );
        for s in self.socket() {
            s.write_message(WsMessage::Text(sub.as_json()))?;
        }
        self.subscriptions.push(id);
        Ok(())
    }

    fn subscribe_to_self(&mut self) -> Result<()> {
        let pk = self.keys.public_key();
        self.subscribe(pk)
    }

    fn socket_writer(&mut self, event: &Event) -> Result<()> {
        for s in self.socket() {
            s.write_message(WsMessage::Text(
                ClientMessage::new_event(event.clone()).as_json(),
            ))?
        }
        Ok(())
    }

    fn socket_reader(&mut self, mmr: &mut Mmr) -> Result<()> {
        for s in self.socket() {
            let msg = s.read_message()?;
            let msg_text = msg.to_text().expect("Failed to convert message to text");
            let handled_message = RelayMessage::from_json(msg_text)?;
            match handled_message {
                RelayMessage::Empty => {
                    println!("Empty message")
                }
                RelayMessage::Notice { message } => {
                    println!("Got a notice: {}", message);
                }
                RelayMessage::EndOfStoredEvents(_subscription_id) => {
                    println!("Relay signalled End of Stored Events");
                }
                RelayMessage::Ok {
                    event_id,
                    status,
                    message,
                } => {
                    println!("Got OK message: {} - {} - {}", event_id, status, message);
                }
                RelayMessage::Event {
                    event,
                    subscription_id: _,
                } => {
                    // check if MMR event
                    //
                    if mmr.node_pos.contains_key(&(&event.id).into()){
                        eprintln!("EventAlreadyInMmr");
                        Err(Error::EventAlreadyInMmr)?
                    }
                    if MmrTag::try_from(&*event).map(|mmr_tag| mmr_tag == mmr.last_mmr_tag())?
                        && event.verify().is_ok()
                    {
                        mmr.push((&event.id).into())?;
                        println!("valid mmr, appending");
                        println!("{:#?}", event);
                    } else {
                        eprintln!("invalid mmr, ignoring");
                    }
                }
                relay_msg => println!("unhandledRelayMessage {:#?}", relay_msg),
            }
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    publisher_runtime().and_then(validator_runtime)
}

fn validator_runtime(publisher_pk: XOnlyPublicKey) -> Result<()> {
    let keys = Keys::generate();
    let mut runtime = Runtime {
        keys,
        sockets: Default::default(),
        subscriptions: Default::default(),
    };

    let mut backend = VecBackend::<EventId>::new();
    let mut mmr = Mmr::new(&mut backend);
    runtime.connect("wss://nostr-pub.wellorder.net")?;
    runtime.connect("wss://relay.damus.io")?;
    runtime.connect("wss://nostr.rocks")?;
    runtime.subscribe(publisher_pk)?;

    println!("############################################################################");
    println!("############################################################################");
    println!("############################################################################");
    println!("############################################################################");
    println!("############################################################################");
    println!("############################################################################");
    println!("validator runtime");
    println!("############################################################################");
    for _ in 0..10 {
        let _ = runtime.socket_reader(&mut mmr);
    }

    Ok(())
}

fn publisher_runtime() -> Result<XOnlyPublicKey> {
    env_logger::init();
    let keys = Keys::generate();
    let publisher_pk = keys.public_key();
    let mut runtime = Runtime {
        keys,
        sockets: Default::default(),
        subscriptions: Default::default(),
    };

    runtime.connect("wss://nostr-pub.wellorder.net")?;
    runtime.connect("wss://relay.damus.io")?;
    runtime.connect("wss://nostr.rocks")?;

    runtime.subscribe_to_self()?;

    let mut backend = VecBackend::<EventId>::new();
    let mut mmr = Mmr::new(&mut backend);

    // send some msgs
    for n in 0..8 {
        println!("\n####msg{}", n);
        let msg = format!("This is Nostr message number {} with embedded MMR", n);
        let ev = mmr.new_event(&msg, &runtime.keys)?;
        runtime.socket_writer(&ev)?;
        runtime.socket_reader(&mut mmr);
    }
    runtime.socket_reader(&mut mmr);
    Ok(publisher_pk)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventId(Sha256Hash);

impl From<&nostr::EventId> for EventId {
    fn from(value: &nostr::EventId) -> Self {
        Self(value.inner())
    }
}

impl DefaultHashable for EventId {}

impl PMMRable for EventId {
    type E = Self;

    fn as_elmt(&self) -> Self::E {
        *self
    }

    fn elmt_size() -> Option<u16> {
        Some(Sha256Hash::LEN as u16)
    }
}

impl Writeable for EventId {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), cloud_mmr::ser::Error> {
        writer.write_bytes(self.0.to_byte_array())
    }
}

impl Readable for EventId {
    fn read<R: Reader>(reader: &mut R) -> Result<EventId, cloud_mmr::ser::Error> {
        let byte_array: [u8; 32] = reader
            .read_fixed_bytes(Sha256Hash::LEN)?
            .try_into()
            .map_err(|_| cloud_mmr::ser::Error::CorruptedData)?;
        //         Ok(EventId(
        //             Sha256Hash::from_slice(byte_array.as_ref())
        //                 .map_err(|_| cloud_mmr::ser::Error::CorruptedData)?,
        //         ))
        Ok(EventId(Sha256Hash::from_byte_array(byte_array)))
    }
}
