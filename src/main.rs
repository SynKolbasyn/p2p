//!   p2p. P2P messaging network.
//!   Copyright (C) 2024  Andrew Kozmin
//!   
//!   This program is free software: you can redistribute it and/or modify
//!   it under the terms of the GNU Affero General Public License as published
//!   by the Free Software Foundation, either version 3 of the License, or
//!   (at your option) any later version.
//!   
//!   This program is distributed in the hope that it will be useful,
//!   but WITHOUT ANY WARRANTY; without even the implied warranty of
//!   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//!   GNU Affero General Public License for more details.
//!   
//!   You should have received a copy of the GNU Affero General Public License
//!   along with this program.  If not, see <https://www.gnu.org/licenses/>.


mod server;
mod server_list;


use std::{
  net::{Ipv4Addr, Ipv6Addr},
  time::Duration,
  io::Write,
};

use anyhow::{Result, Context};
use tokio::io::{AsyncBufReadExt, Lines, Stdin, BufReader, stdin};
use libp2p::{
  futures::StreamExt,
  gossipsub::{self, MessageAuthenticity, Topic, Sha256Topic, Message},
  identify,
  identity::{Keypair, PublicKey},
  kad::{self, store::MemoryStore, PROTOCOL_NAME},
  multiaddr::Protocol,
  noise,
  swarm::{Config, NetworkBehaviour, Swarm, SwarmEvent},
  tcp,
  tls,
  yamux,
  Multiaddr,
  PeerId,
  SwarmBuilder,
};

use crate::server::server_main;
use crate::server_list::ServerList;


#[tokio::main]
async fn main() -> Result<()> {
  if is_server()? {
    server_main().await?;
    return Ok(());
  }

  let key: Keypair = Keypair::generate_ed25519();

  let behaviour: Behaviour = Behaviour::from_key(key.clone())?;

  let mut swarm: Swarm<Behaviour> = SwarmBuilder::with_existing_identity(key.clone())
  .with_tokio()
  .with_tcp(
    tcp::Config::default(),
    (tls::Config::new, noise::Config::new),
    yamux::Config::default,
  )?
  .with_quic()
  .with_dns()?
  .with_behaviour(|_| -> Behaviour {
    behaviour
  })?
  .with_swarm_config(|config: Config| -> Config {
    config.with_idle_connection_timeout(Duration::from_secs(u64::MAX))
  })
  .build();

  let addr_v4_tcp = Multiaddr::empty()
  .with(Protocol::from(Ipv4Addr::UNSPECIFIED))
  .with(Protocol::Tcp(0));

  let addr_v6_tcp = Multiaddr::empty()
  .with(Protocol::from(Ipv6Addr::UNSPECIFIED))
  .with(Protocol::Tcp(0));
  
  let addr_v4_udp = Multiaddr::empty()
  .with(Protocol::from(Ipv4Addr::UNSPECIFIED))
  .with(Protocol::Udp(0))
  .with(Protocol::QuicV1);

  let addr_v6_udp = Multiaddr::empty()
  .with(Protocol::from(Ipv6Addr::UNSPECIFIED))
  .with(Protocol::Udp(0))
  .with(Protocol::QuicV1);
  
  swarm.listen_on(addr_v4_tcp)?;
  swarm.listen_on(addr_v6_tcp)?;
  swarm.listen_on(addr_v4_udp)?;
  swarm.listen_on(addr_v6_udp)?;

  if let Ok(server_list) = ServerList::from_path("server_list.json") {
    for (peer_id, addresses) in server_list.addresses.iter() {
      addresses.values().for_each(|addr: &Multiaddr| {
        swarm.behaviour_mut().kademlia.add_address(peer_id, addr.clone());
      });
    }
  }
  else {
    let server_id: String = std::env::args().nth(1).context("Server ID isn't provided")?;
    let server_ip: String = std::env::args().nth(2).context("Server IP isn't provided")?;
    swarm.behaviour_mut().kademlia.add_address(&server_id.parse()?, server_ip.parse()?);
  }
  swarm.behaviour_mut().kademlia.bootstrap()?;

  let mut stdin: Lines<BufReader<Stdin>> = BufReader::new(stdin()).lines();

  let topic: Topic<_> = Sha256Topic::new("topic");
  swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

  println!("{}", swarm.local_peer_id());

  loop {
    tokio::select! {
      event = swarm.select_next_some() => match event {
        SwarmEvent::Behaviour(event) => {
          match event {
            BehaviourEvent::Identify(event) => match event {
              identify::Event::Received { peer_id, info: identify::Info { listen_addrs, .. }, .. } => {
                listen_addrs.iter().for_each(|addr: &Multiaddr| {
                  swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                });
              },
  
              identify::Event::Sent { .. } => (),
              identify::Event::Pushed { .. } => (),
              identify::Event::Error { .. } => (),
            },

            BehaviourEvent::Kademlia(event) => match event {
              kad::Event::InboundRequest { .. } => (),
              kad::Event::OutboundQueryProgressed { .. } => (),
              kad::Event::RoutingUpdated { .. } => (),
              kad::Event::UnroutablePeer { .. } => (),
              kad::Event::RoutablePeer { .. } => (),
              kad::Event::PendingRoutablePeer { .. } => (),
              kad::Event::ModeChanged { .. } => (),
            },

            BehaviourEvent::Gossipsub(event) => match event {
              gossipsub::Event::Message { message: Message { data, .. } , .. } => println!("{}", String::from_utf8(data)?),
              gossipsub::Event::Subscribed { .. } => (),
              gossipsub::Event::Unsubscribed { .. } => (),
              gossipsub::Event::GossipsubNotSupported { .. } => (),
            },
          }
        },

        SwarmEvent::ConnectionEstablished { .. } => (),
        SwarmEvent::ConnectionClosed { .. } => (),
        SwarmEvent::IncomingConnection { .. } => (),
        SwarmEvent::IncomingConnectionError { .. } => (),
        SwarmEvent::OutgoingConnectionError { .. } => (),
        SwarmEvent::NewListenAddr { .. } => (),
        SwarmEvent::ExpiredListenAddr { .. } => (),
        SwarmEvent::ListenerClosed { .. } => (),
        SwarmEvent::ListenerError { .. } => (),
        SwarmEvent::Dialing { .. } => (),
        SwarmEvent::NewExternalAddrCandidate { .. } => (),
        SwarmEvent::ExternalAddrConfirmed { .. } => (),
        SwarmEvent::ExternalAddrExpired { .. } => (),
        SwarmEvent::NewExternalAddrOfPeer { .. } => (),

        _ => (),
      },

      Ok(Some(line)) = stdin.next_line() => {
        swarm.behaviour_mut().gossipsub.publish(topic.clone(), line)?;
      },
    }
  }
}


fn is_server() -> Result<bool> {
  let mut answer: String = String::new();

  print!("Do you want to use the program as a server? [Y/n]: ");
  std::io::stdout().flush()?;

  std::io::stdin().read_line(&mut answer)?;

  Ok(match answer.to_lowercase().trim() {
    "y" => true,
    "yes" => true,
    _ => false,
  })
}


#[derive(NetworkBehaviour)]
struct Behaviour {
  gossipsub: gossipsub::Behaviour,
  identify: identify::Behaviour,
  kademlia: kad::Behaviour<MemoryStore>,
}


impl Behaviour {
  fn new(
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
  ) -> Self {
    Self {
      gossipsub,
      identify,
      kademlia,
    }
  }


  fn from_key(key: Keypair) -> Result<Self> {
    let publick_key: PublicKey = key.public();
    let peer_id: PeerId = publick_key.to_peer_id();

    let gossipsub_behaviour: gossipsub::Behaviour = {
      let gossipsub_config: gossipsub::Config = gossipsub::ConfigBuilder::default().build()?;
      let privacy: MessageAuthenticity = MessageAuthenticity::Signed(key.clone());
      gossipsub::Behaviour::new(privacy, gossipsub_config).unwrap()
    };

    let identify_behaviour: identify::Behaviour = {
      let identify_config: identify::Config = identify::Config::new(
        String::from("polkadot/1.0.0"),
        publick_key,
      )
      .with_interval(Duration::from_secs(1));

      identify::Behaviour::new(identify_config)
    };

    let kademlia_behaviour: kad::Behaviour<MemoryStore> = {
      let mut kademlia_config: kad::Config = kad::Config::new(PROTOCOL_NAME);
      kademlia_config.set_query_timeout(Duration::from_secs(u64::MAX));
      kademlia_config.set_publication_interval(Some(Duration::from_secs(1)));
      kademlia_config.set_replication_interval(Some(Duration::from_secs(1)));
      let store: MemoryStore = MemoryStore::new(peer_id);
      kad::Behaviour::with_config(peer_id, store, kademlia_config)
    };

    Ok(Self::new(
      gossipsub_behaviour,
      identify_behaviour,
      kademlia_behaviour,
    ))
  }
}
