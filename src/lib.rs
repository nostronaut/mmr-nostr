pub mod client;

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
use std::collections::HashMap;

pub struct Mmr<'a> {
    mmr: PMMR<'a, EventId, VecBackend<EventId>>,
    node_pos: HashMap<EventId, u64>,
}

impl<'a> Mmr<'a> {
    pub fn new(backend: &'a mut VecBackend<EventId>) -> Self {
        Mmr {
            mmr: PMMR::<EventId, VecBackend<EventId>>::new(backend),
            node_pos: Default::default(),
        }
    }

    pub fn new_event(&mut self, msg: &str, keys: &Keys) -> Result<(Event, MerkleProof)> {
        let event = self.build_event(msg, keys)?;
        let proof = self.handle_event(&event)?;
        // self.push((&event.id).into())?; // <- this is enough
        Ok((event, proof))
    }

    pub fn handle_event(&mut self, event: &nostr::Event) -> Result<MerkleProof> {
        self.verify(event)?;
        self.push((&event.id).into())
    }

    fn verify(&mut self, event: &nostr::Event) -> Result<()> {
        self.doesnt_contain(&(&event.id).into())?;
        let prev_mmr_tag = MmrTag::try_from(event)?;
        // check if the expected mmr_tag matches the  prev_mmr_tag referenced in the new event
        self.last_mmr_tag().equals(&prev_mmr_tag)?;
        event.verify()?;
        Ok(())
    }

    fn push(&mut self, event_id: EventId) -> Result<MerkleProof> {
        self.doesnt_contain(&event_id)?;
        let leaf_pos = self.mmr.push(&event_id)?;
        self.mmr.validate()?;
        println!("Verified pmmr");
        // log_mmr_update(&self.pmmr);
        self.node_pos.insert(event_id, leaf_pos);
        let proof = self.merkle_proof(&event_id).unwrap();
        Ok(proof)
    }

    pub fn last_mmr_tag(&self) -> MmrTag {
        MmrTag {
            prev_event_id: self.last_event_id(),
            prev_mmr_root: self.mmr_root().unwrap_or_else(Sha256Hash::all_zeros),
            prev_event_pos: self
                .last_event_pos()
                .and_then(|pos| pos.try_into().ok())
                .unwrap_or(-1),
        }
    }

    fn build_event(&self, msg: &str, keys: &Keys) -> Result<Event> {
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

    // TODO: return should be Result<MerkleProof>
    fn merkle_proof(&self, event_id: &EventId) -> Option<MerkleProof> {
        self.node_pos
            .get(&event_id)
            .and_then(|node_pos| self.mmr.merkle_proof(*node_pos).ok())
    }

    pub fn doesnt_contain(&self, event_id: &EventId) -> Result<()> {
        if self.node_pos.contains_key(event_id) {
            Err(Box::new(Error::EventAlreadyInMmr))
        } else {
            Ok(())
        }
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
}

#[derive(Eq, PartialEq)]
pub struct MmrTag {
    prev_event_id: Sha256Hash,
    prev_mmr_root: Sha256Hash,
    prev_event_pos: i64,
}

impl MmrTag {
    fn equals(&self, rhs: &MmrTag) -> Result<()> {
        if self == rhs {
            Ok(())
        } else {
            Err(Box::new(Error::MmrTagMismatch))
        }
    }
}

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

#[derive(Debug)]
pub enum Error {
    /// Event doesn't contain MMR tag
    MmrTagMissing,
    /// EventId already present in MMR
    EventAlreadyInMmr,
    /// MmrTag different thatn expected previous mmr tag
    MmrTagMismatch,
}

impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MmrTagMissing => write!(f, "Event doesn't contain MMR tag"),
            Self::EventAlreadyInMmr => write!(f, "EventId already present in MMR"),
            Self::MmrTagMismatch => write!(f, "MmrTag different than expected previous MmrTag"),
        }
    }
}
