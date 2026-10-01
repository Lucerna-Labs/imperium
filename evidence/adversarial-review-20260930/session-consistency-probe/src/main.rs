use imperium_net_mesh::SessionManager;
use imperium_protocol::{PeerId, SessionId};
use std::net::SocketAddr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manager = SessionManager::new();
    let first_peer = PeerId::new();
    let second_peer = PeerId::new();
    let session = SessionId::new();
    let first_address: SocketAddr = "127.0.0.1:41001".parse()?;
    let second_address: SocketAddr = "127.0.0.1:41002".parse()?;

    manager.adopt_session(session.clone(), first_peer.clone(), first_address, false)?;
    let duplicate_result =
        manager.adopt_session(session.clone(), second_peer.clone(), second_address, false);

    let duplicate_accepted = duplicate_result.is_ok();
    let first_mapping_retained = manager.get_session_for_peer(&first_peer) == Some(session.clone());
    let second_mapping_created =
        manager.get_session_for_peer(&second_peer) == Some(session.clone());
    let stored_owner_is_second = manager.session_peer_id(&session) == Some(second_peer);
    let stored_address_is_second = manager.session_remote_addr(&session) == Some(second_address);
    println!("duplicate_accepted={duplicate_accepted}");
    println!("first_mapping_retained={first_mapping_retained}");
    println!("second_mapping_created={second_mapping_created}");
    println!("stored_owner_is_second={stored_owner_is_second}");
    println!("stored_address_is_second={stored_address_is_second}");
    Ok(())
}
