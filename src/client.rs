use super::Mmr;
use nostr::prelude::*;
use std::net::TcpStream;
use tungstenite::{connect, stream::MaybeTlsStream, Message as WsMessage, WebSocket};

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

pub struct Client {
    pub keys: Keys,
    pub sockets: Vec<Socket>,
    pub subscriptions: Vec<SubscriptionId>,
}

impl Client {
    fn socket(&mut self) -> Vec<&mut Socket> {
        self.sockets.iter_mut().collect()
    }

    pub fn connect(&mut self, ws_endpoint: &str) -> Result<()> {
        let (socket, _response) = connect(Url::parse(ws_endpoint)?)?;
        self.sockets.push(socket);
        Ok(())
    }

    pub fn subscribe(&mut self, pk: XOnlyPublicKey) -> Result<()> {
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

    pub fn subscribe_to_self(&mut self) -> Result<()> {
        let pk = self.keys.public_key();
        self.subscribe(pk)
    }

    pub fn socket_writer(&mut self, event: &Event) -> Result<()> {
        for s in self.socket() {
            s.write_message(WsMessage::Text(
                ClientMessage::new_event(event.clone()).as_json(),
            ))?
        }
        Ok(())
    }

    pub fn socket_reader(&mut self, mmr: &mut Mmr) -> Result<()> {
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
                    // TODO: events expected to arrive in order
                    mmr.handle_event(&event)?;
                    println!("received valid mmr event from relay, appending");
                    println!("{:#?}", event);
                }
                relay_msg => println!("unhandledRelayMessage {:#?}", relay_msg),
            }
        }
        Ok(())
    }
}
