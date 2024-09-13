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


use std::{
  collections::HashMap,
  net::{Ipv4Addr, Ipv6Addr},
  time::Duration,
  fs::File,
  path::Path,
};

use anyhow::Result;
use serde::{Serialize, Deserialize};
use tokio::sync::watch::Sender;
use libp2p::{
  rendezvous,
  futures::StreamExt,
  identity::Keypair,
  multiaddr::Protocol,
  core::transport::ListenerId,
  noise,
  identify,
  kad::{self, store::MemoryStore, PROTOCOL_NAME},
  swarm::{Config, Swarm, NetworkBehaviour, SwarmEvent},
  tcp,
  tls,
  yamux,
  Multiaddr,
  SwarmBuilder,
  PeerId,
  identity::PublicKey,
};


pub(crate) async fn server_main(sender: Sender<(PeerId, Option<Multiaddr>, Multiaddr)>) -> Result<()> {
  let key: Keypair = Keypair::generate_ed25519();

  let behaviour: Behaviour = Behaviour::from_key(key.clone())?;

  let mut swarm: Swarm<Behaviour> = SwarmBuilder::with_existing_identity(key)
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

  let mut server_config: ServerConfig = ServerConfig::from(swarm.local_peer_id());

  loop {
    match swarm.select_next_some().await {
      SwarmEvent::NewListenAddr { listener_id, address } => {
        let file: File = File::options().create(true).truncate(true).write(true).open("server_config.json")?;
        serde_json::to_writer_pretty(file, &server_config)?;
        sender.send((swarm.local_peer_id().clone(), server_config.add_addr(listener_id, address.clone()), address))?;
      },

      // event => println!("{event:?}"),
      _ => (),
    }
  }
}


#[derive(NetworkBehaviour)]
struct Behaviour {
  identify: identify::Behaviour,
  // randezvous: rendezvous::server::Behaviour,
  kademlia: kad::Behaviour<MemoryStore>,
}


impl Behaviour {
  fn new(
    identify: identify::Behaviour,
    // randezvous: rendezvous::server::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
  ) -> Self {
    Self {
      identify,
      // randezvous,
      kademlia,
    }
  }


  fn from_key(key: Keypair) -> Result<Self> {
    let publick_key: PublicKey = key.public();
    let peer_id: PeerId = publick_key.to_peer_id();

    let identify_behaviour: identify::Behaviour = {
      let identify_config: identify::Config = identify::Config::new(
        String::from("polkadot/1.0.0"),
        publick_key,
      )
      .with_interval(Duration::from_secs(1));

      identify::Behaviour::new(identify_config)
    };

    let randezvous_behaviour: rendezvous::server::Behaviour = {
      let randezvous_config: rendezvous::server::Config = rendezvous::server::Config::default();
      rendezvous::server::Behaviour::new(randezvous_config)
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
      identify_behaviour,
      // randezvous_behaviour,
      kademlia_behaviour,
    ))
  }
}


#[derive(Serialize, Deserialize)]
pub(crate) struct ServerConfig {
  pub(crate) id: PeerId,
  pub(crate) addresses: HashMap<String, Multiaddr>,
}


impl ServerConfig {
  fn new(
    id: PeerId,
    addresses: HashMap<String, Multiaddr>,
  ) -> Self {
    Self {
      id,
      addresses,
    }
  }

  
  pub(crate) fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
    let file: File = File::options().read(true).open(path)?;
    Ok(serde_json::from_reader(file)?)
  }


  fn add_addr(&mut self, listener_id: ListenerId, addr: Multiaddr) -> Option<Multiaddr> {
    self.addresses.insert(listener_id.to_string(), addr)
  }
}


impl From<&PeerId> for ServerConfig {
  fn from(peer_id: &PeerId) -> Self {
    Self::new(peer_id.clone(), HashMap::new())
  }
}
