use cloud_mmr::pmmr::VecBackend;
use mmr_nostr::{client::Client, EventId, Mmr};
use nostr::prelude::*;
/// demo publisher client publishing MMR events to a normal relay and then
/// a validator client reading them from a relay and validating it
fn main() -> Result<()> {
    publisher_client().and_then(validator_client)
}

/// demo publisher client returning the publisher
/// pubkey for validator client to use to verify
fn publisher_client() -> Result<XOnlyPublicKey> {
    env_logger::init();
    let mut runtime = Client {
        keys: Keys::generate(),
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
        let (ev, _proof) = mmr.new_event(&msg, &runtime.keys)?;
        runtime.socket_writer(&ev)?;
        runtime.socket_reader(&mut mmr);
    }
    runtime.socket_reader(&mut mmr);
    Ok(runtime.keys.public_key())
}

/// demo validator client
fn validator_client(publisher_pk: XOnlyPublicKey) -> Result<()> {
    let mut runtime = Client {
        keys: Keys::generate(),
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
