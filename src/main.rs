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
use std::{collections::HashMap, net::TcpStream, str::FromStr};

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;
type MMR<'a> = PMMR<'a, EventId, VecBackend<EventId>>;

struct Runtime<'a> {
    keys: Keys,
    mmr: MMR<'a>,
    node_pos: HashMap<EventId, u64>,
    sockets: Vec<Socket>,
    subscriptions: Vec<SubscriptionId>,
}

impl<'a> Runtime<'a> {
    fn socket(&mut self) -> Option<&mut Socket> {
        self.sockets.first_mut()
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

    fn socket_reader(&mut self) -> Result<()> {
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
                    println!("{:#?}", event);
                    // check if MMR event
                    if is_mmr_event(&event) {
                        println!("found mmr event");
                    }
                }
                relay_msg => println!("unhandledRelayMessage {:#?}", relay_msg),
            }
        }
        Ok(())
    }

    fn new_mmr_event(&mut self, msg: &str) -> Result<Event> {
        let event = self.mmr_event(msg)?;
        self.mmr_append((&event.id).into())?;
        Ok(event)
    }

    fn mmr_event(&self, msg: &str) -> Result<Event> {
        let builder = EventBuilder::new_text_note(msg, &[]);
        let event: Event = builder.to_mmr_event(
            &self.keys,
            last_event_id(&self.mmr),
            mmr_root(&self.mmr).unwrap(),
            last_event_pos(&self.mmr)
                .and_then(|pos| pos.try_into().ok())
                .unwrap_or(-1),
        )?;
        event.verify()?;
        println!("Verified {:#?}", event);
        Ok(event)
    }

    fn mmr_append(&mut self, event_id: EventId) -> Result<MerkleProof> {
        let leaf_pos = self.mmr.push(&event_id)?;
        self.mmr.validate()?;
        println!("Verified pmmr");
        // log_mmr_update(&self.pmmr);
        self.node_pos.insert(event_id, leaf_pos);
        let proof = self.merkle_proof(&event_id).unwrap();
        Ok(proof)
    }

    fn merkle_proof(&self, event_id: &EventId) -> Option<MerkleProof> {
        self.node_pos
            .get(&event_id)
            .and_then(|node_pos| self.mmr.merkle_proof(*node_pos).ok())
    }

    fn is_mmr_member(&self, event_id: &EventId) -> bool {
        self.node_pos.get(event_id).is_some()
    }
}

fn main() -> Result<()> {
    publisher_runtime().and_then(validator_runtime)
}

fn validator_runtime(publisher_pk: XOnlyPublicKey) -> Result<()> {
    let keys = Keys::generate();
    let mut backend = VecBackend::<EventId>::new();
    let mmr = MMR::new(&mut backend);
    let mut runtime = Runtime {
        keys,
        mmr,
        node_pos: Default::default(),
        sockets: Default::default(),
        subscriptions: Default::default(),
    };
    runtime.connect("wss://nostr-pub.wellorder.net")?;
    runtime.connect("wss://relay.damus.io")?;
    runtime.connect("wss://nostr.rocks")?;
    runtime.subscribe(publisher_pk)?;

    println!("######################################");
    println!("######################################");
    println!("######################################");
    println!("######################################");
    println!("######################################");
    println!("######################################");
    println!("validator runtime");
    for n in 0..100 {
        let _ = runtime.socket_reader();
    }

    Ok(())
}

fn publisher_runtime() -> Result<XOnlyPublicKey> {
    env_logger::init();
    let keys = Keys::generate();
    let mut backend = VecBackend::<EventId>::new();
    let publisher_pk = keys.public_key();
    let pmmr = MMR::new(&mut backend);
    let mut runtime = Runtime {
        keys,
        mmr: pmmr,
        node_pos: Default::default(),
        sockets: Default::default(),
        subscriptions: Default::default(),
    };

    runtime.connect("wss://nostr-pub.wellorder.net")?;
    runtime.connect("wss://relay.damus.io")?;
    runtime.connect("wss://nostr.rocks")?;

    runtime.subscribe_to_self()?;

    // send some msgs
    for n in 0..8 {
        println!("\n####msg{}", n);
        let msg = format!("This is Nostr message number {} with embedded MMR", n);
        let ev = runtime.new_mmr_event(&msg)?;
        runtime.socket_writer(&ev)?;
        runtime.socket_reader();
    }
    runtime.socket_reader();
    Ok(publisher_pk)
}

fn log_mmr_update(pmmr: &MMR) {
    println!("mmr updated");
    println!("mmr_root: {:#?}", mmr_root(&pmmr).unwrap());
    println!("event_id_hash: {:#?}", &last_event_hash(&pmmr));
    println!("event_id: {:#?}", &last_event_id(&pmmr));
}

fn mmr_root(pmmr: &MMR) -> Option<Sha256Hash> {
    pmmr.root().ok().as_ref().and_then(convert_hash)
}

fn convert_hash(hash: &Hash) -> Option<Sha256Hash> {
    Sha256Hash::from_slice(hash.as_ref()).ok()
}

fn last_event_pos(pmmr: &MMR) -> Option<u64> {
    pmmr.leaf_pos_iter().last()
}

fn last_event_id(pmmr: &MMR) -> Sha256Hash {
    last_event_pos(pmmr)
        .and_then(|ix| pmmr.get_data(ix))
        .map(|id| id.0)
        .unwrap_or_else(Sha256Hash::all_zeros)
}

fn last_event_hash(pmmr: &MMR) -> Sha256Hash {
    last_event_pos(pmmr)
        .and_then(|ix| pmmr.get_hash(ix))
        .as_ref()
        .and_then(convert_hash)
        .unwrap_or_else(Sha256Hash::all_zeros)
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

fn verify_merkle_proof(proof: MerkleProof, root: Hash, elem: &EventId, node_pos: u64) -> bool {
    if let Ok(_) = proof.verify(root, elem, node_pos) {
        true
    } else {
        false
    }
}

fn is_mmr_event(event: &nostr::Event) -> bool {
    event
        .tags
        .iter()
        .any(|tag| matches!(tag, Tag::Mmr { .. }) || matches!(tag, Tag::Generic(TagKind::Mmr, ..)))
}
