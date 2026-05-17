use std::collections::HashMap;
use std::sync::Arc;

use quinn::Connection;
use rustls::pki_types::CertificateDer;

use crate::{ClientIdentity, ServerTunnelSettings, client_identity_from_certificate_der};

use super::active_client::ActiveClientSlot;

#[derive(Clone)]
pub(crate) struct TunnelRegistry {
    client_identity_to_tunnel: Arc<HashMap<ClientIdentity, usize>>,
    public_hostname_to_tunnel: Arc<HashMap<String, usize>>,
    tunnel_slots: Arc<Vec<ActiveClientSlot>>,
}

impl TunnelRegistry {
    pub(crate) fn single(public_hostnames: Vec<String>) -> Self {
        let public_hostname_to_tunnel = public_hostnames
            .into_iter()
            .map(|hostname| (hostname, 0))
            .collect();
        Self {
            client_identity_to_tunnel: Arc::new(HashMap::new()),
            public_hostname_to_tunnel: Arc::new(public_hostname_to_tunnel),
            tunnel_slots: Arc::new(vec![ActiveClientSlot::new()]),
        }
    }

    pub(crate) fn configured(tunnels: &[ServerTunnelSettings]) -> Self {
        let mut client_identity_to_tunnel = HashMap::new();
        let mut public_hostname_to_tunnel = HashMap::new();
        let mut tunnel_slots = Vec::with_capacity(tunnels.len());
        for (index, tunnel) in tunnels.iter().enumerate() {
            client_identity_to_tunnel.insert(tunnel.client_identity.clone(), index);
            for hostname in &tunnel.public_hostnames {
                public_hostname_to_tunnel.insert(hostname.clone(), index);
            }
            tunnel_slots.push(ActiveClientSlot::new());
        }
        Self {
            client_identity_to_tunnel: Arc::new(client_identity_to_tunnel),
            public_hostname_to_tunnel: Arc::new(public_hostname_to_tunnel),
            tunnel_slots: Arc::new(tunnel_slots),
        }
    }

    pub(crate) async fn current_connection(&self, public_hostname: &str) -> Option<Connection> {
        let tunnel_index = self
            .public_hostname_to_tunnel
            .get(public_hostname)
            .copied()?;
        self.tunnel_slots[tunnel_index].current_connection().await
    }

    pub(crate) fn contains_public_hostname(&self, public_hostname: &str) -> bool {
        self.public_hostname_to_tunnel.contains_key(public_hostname)
    }

    pub(crate) async fn register(&self, connection: Connection) {
        let Some(tunnel_index) = self.tunnel_index_for_connection(&connection) else {
            connection.close(0_u32.into(), b"unmapped client identity");
            return;
        };
        self.tunnel_slots[tunnel_index].register(connection).await;
    }

    fn tunnel_index_for_connection(&self, connection: &Connection) -> Option<usize> {
        if self.client_identity_to_tunnel.is_empty() {
            return Some(0);
        }
        let identity = client_identity_from_connection(connection)?;
        self.client_identity_to_tunnel.get(&identity).copied()
    }
}

fn client_identity_from_connection(connection: &Connection) -> Option<ClientIdentity> {
    let identity = connection.peer_identity()?;
    let certificate_chain = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let certificate = certificate_chain.first()?;
    client_identity_from_certificate_der(certificate.as_ref()).ok()
}
