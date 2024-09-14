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
  net::{Ipv4Addr, Ipv6Addr},
  time::Duration,
};

use anyhow::Result;
use libp2p::{
  futures::StreamExt,
  identity::Keypair,
  multiaddr::Protocol,
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

use crate::server_list::ServerList;


pub(crate) async fn server_main() -> Result<()> {
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

  swarm.behaviour_mut().kademlia.set_mode(Some(kad::Mode::Server));

  let mut server_list: ServerList = ServerList::default();

  println!("{}", swarm.local_peer_id());

  loop {
    match swarm.select_next_some().await {
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
        }
      },

      SwarmEvent::ConnectionEstablished { .. } => (),
      SwarmEvent::ConnectionClosed { .. } => (),
      SwarmEvent::IncomingConnection { .. } => (),
      SwarmEvent::IncomingConnectionError { .. } => (),
      SwarmEvent::OutgoingConnectionError { .. } => (),

      SwarmEvent::NewListenAddr { listener_id, address } => {
        server_list.add_addr_and_save("server_list.json", swarm.local_peer_id().clone(), listener_id, address)?;
      },

      SwarmEvent::ExpiredListenAddr { .. } => (),
      SwarmEvent::ListenerClosed { .. } => (),
      SwarmEvent::ListenerError { .. } => (),
      SwarmEvent::Dialing { .. } => (),
      SwarmEvent::NewExternalAddrCandidate { .. } => (),
      SwarmEvent::ExternalAddrConfirmed { .. } => (),
      SwarmEvent::ExternalAddrExpired { .. } => (),
      SwarmEvent::NewExternalAddrOfPeer { .. } => (),

      _ => (),
    }
  }
}


#[derive(NetworkBehaviour)]
struct Behaviour {
  identify: identify::Behaviour,
  kademlia: kad::Behaviour<MemoryStore>,
}


impl Behaviour {
  fn new(
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
  ) -> Self {
    Self {
      identify,
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
      kademlia_behaviour,
    ))
  }
}
