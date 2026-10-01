//! Kernel transport control only. Refuses execution outside a private user/net namespace.
use imperium_net_host::{KernelDisposition, PacketQueue};
use std::error::Error;
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn Error>> {
    if std::env::var("IMPERIUM_QUEUE_LAB").as_deref() != Ok("1")
        || std::fs::read_link("/proc/self/ns/net")? == std::fs::read_link("/proc/1/ns/net")?
        || std::fs::read_link("/proc/self/ns/user")? == std::fs::read_link("/proc/1/ns/user")?
    {
        return Err(
            "queue lab requires explicit lab marker and private user/network namespaces".into(),
        );
    }
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: queue_lab QUEUE accept|drop SECONDS".into());
    }
    let disposition = match args[2].as_str() {
        "accept" => KernelDisposition::Release,
        "drop" => KernelDisposition::Discard,
        _ => return Err("unknown mechanical control mode".into()),
    };
    let seconds: u64 = args[3].parse()?;
    if seconds == 0 || seconds > 60 {
        return Err("lab duration outside 1..60 seconds".into());
    }
    let mut queue = PacketQueue::bind(args[1].parse()?, 64)?;
    println!("READY");
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut count = 0;
    while Instant::now() < deadline {
        if let Some(packet) = queue.receive(Duration::from_millis(100))? {
            println!(
                "PACKET id={} family={} hook={} bytes={}",
                packet.id(),
                packet.family,
                packet.hook,
                packet.bytes().len()
            );
            queue.finish(packet, disposition)?;
            count += 1;
        }
    }
    println!("FINISHED count={count}");
    Ok(())
}
