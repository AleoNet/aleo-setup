use std::fmt::Debug;

use anyhow::{anyhow, Result};
use futures::{Sink, SinkExt};
use setup1_shared::reliability::ContributorMessage;
use tokio_tungstenite::tungstenite::protocol::Message;

pub(super) async fn check<W>(write_half: &mut W, data: Vec<u8>) -> Result<()>
where
    W: Sink<Message> + Unpin,
    W::Error: Debug,
{
    let challenge = ContributorMessage::BandwidthChallenge(data);
    let response = Message::binary(challenge.encode()?);
    write_half.send(response).await.map_err(|e| anyhow!("{:?}", e))?;
    Ok(())
}
