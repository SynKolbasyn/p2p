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
