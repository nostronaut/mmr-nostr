use cloud_mmr::{
    self,
    hash::{DefaultHashable, Hash},
    pmmr::{ReadablePMMR, VecBackend, PMMR},
    ser::{PMMRable, Readable, Reader, Writeable, Writer},
};

use bitcoin_hashes::sha256::Hash as Sha256Hash;
use bitcoin_hashes::Hash as BitcoinHash;

use nostr::prelude::*;
use std::str::FromStr;

fn main() {
    const ALICE_SK: &str = "6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e";

    fn main() -> Result<()> {
        env_logger::init();

        let secret_key = SecretKey::from_str(ALICE_SK)?;
        let alice_keys = Keys::new(secret_key);
        let mut backend = VecBackend::<EventId>::new();
        let mut pmmr = cloud_mmr::pmmr::PMMR::new(&mut backend);

        // msg0
        println!("\n####msg0");
        let msg = "This is a Nostr message with embedded MMR";
        let _ev = mmr_event(msg, &mut pmmr, &alice_keys)?;

        // msg1
        println!("\n####msg1");
        let msg = "This is another Nostr message with embedded MMR";
        let _ev = mmr_event(msg, &mut pmmr, &alice_keys)?;

        // msg2
        println!("\n####msg2");
        let msg = "This is yet another Nostr message with embedded MMR";
        let _ev = mmr_event(msg, &mut pmmr, &alice_keys)?;
        Ok(())
    }
    main().unwrap();
}

fn mmr_event(
    msg: &str,
    pmmr: &mut PMMR<EventId, VecBackend<EventId>>,
    alice_keys: &Keys,
) -> Result<Event> {
    let builder = EventBuilder::new_text_note(msg, &[]);
    let event: Event = builder.to_mmr_event(
        &alice_keys,
        event_id(&pmmr).unwrap(),
        mmr_root(&pmmr).unwrap(),
    )?;
    event.verify()?;
    println!("Verified {:#?}", event);
    let event_id = EventId(event.id.inner());
    pmmr.push(&event_id)?;
    pmmr.validate()?;
    log_mmr_update(&pmmr);
    Ok(event)
}

fn log_mmr_update(pmmr: &PMMR<EventId, VecBackend<EventId>>) {
    println!("mmr updated");
    println!("mmr_root: {:#?}", mmr_root(&pmmr).unwrap());
    println!("event_id_hash: {:#?}", &event_hash(&pmmr).unwrap());
    println!("event_id: {:#?}", &event_id(&pmmr).unwrap());
}

fn mmr_root(pmmr: &PMMR<EventId, VecBackend<EventId>>) -> Option<Sha256Hash> {
    pmmr.root().ok().and_then(|ref h| convert_hash(h))
}

fn convert_hash(hash: &Hash) -> Option<Sha256Hash> {
    Sha256Hash::from_slice(hash.as_ref()).ok()
}

fn event_id(pmmr: &PMMR<EventId, VecBackend<EventId>>) -> Option<Sha256Hash> {
    if pmmr.size == 0 {
        Some(Sha256Hash::all_zeros())
    } else {
        pmmr.leaf_pos_iter()
            .last()
            .and_then(|ix| pmmr.get_data(ix))
            .map(|id| id.0)
    }
}

fn event_hash(pmmr: &PMMR<EventId, VecBackend<EventId>>) -> Option<Sha256Hash> {
    if pmmr.size == 0 {
        Some(Sha256Hash::all_zeros())
    } else {
        pmmr.leaf_pos_iter()
            .last()
            .and_then(|ix| pmmr.get_hash(ix))
            .and_then(|ref h| convert_hash(h))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EventId(Sha256Hash);

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
