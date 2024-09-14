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
  fs::File,
  path::Path,
  collections::HashMap,
};

use anyhow::Result;
use serde::{Serialize, Deserialize};
use libp2p::{
  PeerId,
  Multiaddr,
  core::transport::ListenerId,
};


#[derive(Serialize, Deserialize)]
pub(crate) struct ServerList {
  pub(crate) addresses: HashMap<PeerId, HashMap<String, Multiaddr>>,
}


impl ServerList {
  fn new(addresses: HashMap<PeerId, HashMap<String, Multiaddr>>) -> Self {
    Self {
      addresses,
    }
  }

  
  pub(crate) fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
    let file: File = File::options().truncate(false).read(true).open(path)?;
    Ok(serde_json::from_reader(file)?)
  }


  pub(crate) fn add_addr(&mut self, peer_id: PeerId, listener_id: ListenerId, multiaddr: Multiaddr) {
    let mut addresses: HashMap<String, Multiaddr> = HashMap::new();
    if let Some(addr) = self.addresses.get(&peer_id) {
      addresses = addr.clone();
    }
    addresses.insert(listener_id.to_string(), multiaddr);
    self.addresses.insert(peer_id, addresses);
  }


  pub(crate) fn add_addr_and_save<P: AsRef<Path>>(&mut self, path: P, peer_id: PeerId, listener_id: ListenerId, multiaddr: Multiaddr) -> Result<()> {
    self.add_addr(peer_id, listener_id, multiaddr);
    self.save(path)?;
    Ok(())
  }


  pub(crate) fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
    let file: File = File::options().create(true).truncate(true).write(true).open(path)?;
    serde_json::to_writer_pretty(file, self)?;
    Ok(())
  }
}


impl Default for ServerList {
  fn default() -> Self {
    Self::new(HashMap::default())
  }
}
