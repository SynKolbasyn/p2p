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


// #![allow(unreachable_code)]
// #![allow(unused_imports)]
// #![allow(unused_variables)]


mod server;


use std::num::NonZeroUsize;
use std::ops::Add;
use std::{
  net::{Ipv4Addr, Ipv6Addr},
  time::{Duration, Instant},
  io::Write,
  path::Path,
};

use anyhow::{Result, Context};
use tokio::{
  io::{AsyncBufReadExt, Lines, Stdin, BufReader, stdin},
  sync::watch::{self, Receiver, Sender},
  task,
};
use libp2p::{
  futures::StreamExt,
  gossipsub::{self, MessageAuthenticity, IdentTopic, Topic},
  rendezvous,
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
  bytes::BufMut,
};

use crate::server::{ServerConfig, server_main};


#[tokio::main]
async fn main() -> Result<()> {
  // let key: Keypair = Keypair::ed25519_from_bytes([10])?;

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
  println!("{}", swarm.local_peer_id());

  let (_server_handle, server_receiver): (Option<task::JoinHandle<Result<()>>>, Option<Receiver<(PeerId, Option<Multiaddr>, Multiaddr)>>) = if is_server_neded()? {
    let (sender, receiver): (Sender<(PeerId, Option<Multiaddr>, Multiaddr)>, Receiver<(PeerId, Option<Multiaddr>, Multiaddr)>) = watch::channel((PeerId::random(), None, Multiaddr::empty()));
    (Some(task::spawn(async { server_main(sender).await })), Some(receiver))
  }
  else {
    let server_config_path: &Path = Path::new("server_config.json");
    if server_config_path.exists() {
      let server_config: ServerConfig = ServerConfig::from_path(server_config_path)?;

      for addr in server_config.addresses.values() {
        swarm.behaviour_mut().kademlia.add_address(&server_config.id, addr.clone());
      }
    }
    else {
      let server_id: String = std::env::args().nth(1).context("Server ID isn't provided")?;
      let server_ip: String = std::env::args().nth(2).context("Server IP isn't provided")?;
      swarm.behaviour_mut().kademlia.add_address(&server_id.parse()?, server_ip.parse()?);
    }
    (None, None)
  };

  let mut stdin: Lines<BufReader<Stdin>> = BufReader::new(stdin()).lines();
  let topic = IdentTopic::new("topic");

  loop {
    if server_receiver.is_some() {
      let mut rx: Receiver<(PeerId, Option<Multiaddr>, Multiaddr)> = server_receiver.clone().unwrap();
      tokio::select! {
        event = swarm.select_next_some() => event_process(&mut swarm, event)?,
  
        _ = rx.changed() => {
          let (server_id, prev_ip, new_ip) = rx.borrow_and_update().clone();
          if prev_ip.is_some() {
            swarm.behaviour_mut().kademlia.remove_address(&server_id, &prev_ip.unwrap());
          }
          swarm.behaviour_mut().kademlia.add_address(&server_id, new_ip);
        },

        Ok(Some(line)) = stdin.next_line() => {
          println!("{:?}", swarm.behaviour_mut().kademlia.get_closest_peers(key.public().to_peer_id()));
          if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), line.as_bytes()) {
            println!("Publish error: {e:?}");
          }
        },
      }
    }
    else {
      tokio::select! {
        event = swarm.select_next_some() => event_process(&mut swarm, event)?,

        Ok(Some(line)) = stdin.next_line() => {
          if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), line.as_bytes()) {
            println!("Publish error: {e:?}");
          }
        },
      }
    }
  }

  // if server_handle.is_some() {
  //   server_handle.unwrap().abort();
  // }

  // Ok(())
}


fn event_process(swarm: &mut Swarm<Behaviour>, event: SwarmEvent<BehaviourEvent>) -> Result<()> {
  // let server_config: ServerConfig = ServerConfig::from_path("server_config.json")?;

  match event {
    SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
      propagation_source: peer_id,
      message_id: id,
      message,
    })) => println!("Got message: '{}' with id: {id} from peer: {peer_id}", String::from_utf8_lossy(&message.data)),

    SwarmEvent::ConnectionEstablished { peer_id, .. } if true /*peer_id == server_config.id*/ => {
      if let Err(e) = swarm.behaviour_mut().rendezvous.register(rendezvous::Namespace::from_static("rendezvous"), peer_id, None) {
        eprintln!("Failed to register: {e}");
      }
    }

    SwarmEvent::Behaviour(BehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
      result: kad::QueryResult::GetClosestPeers(Ok(ok)),
      ..
    })) => {
      for i in ok.peers {
        println!("Discovered {}", i.peer_id);
      }
    },

    SwarmEvent::Behaviour(BehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
      result,
      ..
    })) => {
      println!("{:?}", result);
    },

    SwarmEvent::Behaviour(BehaviourEvent::Kademlia(kad::Event::RoutingUpdated {
      peer,
      is_new_peer,
      ..
    })) => {
      println!("Routing updated: {peer}");
      // if is_new_peer { swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer) }
    },

    _ => println!("{event:?}"),
    // _ => (),
  }

  Ok(())
}


fn is_server_neded() -> Result<bool> {
  let mut answer: String = String::new();

  print!("Do you need a server? [Y/n]: ");
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
  rendezvous: rendezvous::client::Behaviour,
}


impl Behaviour {
  fn new(
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
    rendezvous: rendezvous::client::Behaviour,
  ) -> Self {
    Self {
      gossipsub,
      identify,
      kademlia,
      rendezvous
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

    let rendezvous_behaviour: rendezvous::client::Behaviour = rendezvous::client::Behaviour::new(key);

    Ok(Self::new(
      gossipsub_behaviour,
      identify_behaviour,
      kademlia_behaviour,
      rendezvous_behaviour,
    ))
  }
}
