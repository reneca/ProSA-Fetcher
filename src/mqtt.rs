//! MQTT 3.1.1 client session, opened by an adaptor with [`FetchAction::Mqtt`](crate::proc::FetchAction::Mqtt).

use std::{fmt, io, time::Duration};

use bytes::{Bytes, BytesMut};
use prosa::{
    io::stream::{Stream, TargetSetting},
    tracing::{debug, info, warn},
};
use rumqttc::mqttbytes::v4::{
    ConnAck, Connect, Login, Packet, PubAck, PubComp, PubRec, Subscribe, SubscribeFilter,
    SubscribeReasonCode,
};
pub use rumqttc::mqttbytes::{Error as MqttCodecError, QoS, v4::ConnectReturnCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::{mpsc, oneshot},
    time,
};

use crate::proc::{AbortOnDropJoinHandle, FetcherError};

const EVENT_CHANNEL_CAPACITY: usize = 32;
const READ_CHUNK_SIZE: usize = 4096;

/// MQTT protocol error
#[derive(Debug, Error)]
pub enum MqttError {
    /// Packet that can't be encoded or decoded, or that exceeds `max_packet_size`
    #[error("MQTT codec error `{0}`")]
    Codec(#[from] MqttCodecError),
    /// Packet that the client doesn't expect at this stage of the session
    #[error("MQTT broker sent an unexpected packet while waiting for {0}")]
    UnexpectedPacket(&'static str),
}

/// MQTT settings of the fetcher processor
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(default)]
pub struct MqttSettings {
    /// Keep alive interval sent to the broker; a ping is sent at this interval. Zero disables it.
    pub keep_alive: Duration,
    /// Maximum size of an MQTT packet in bytes. A larger packet closes the connection.
    pub max_packet_size: usize,
    /// Delay before the first reconnection, doubled after every failed attempt. Must be greater than zero.
    pub reconnect_min: Duration,
    /// Maximum delay between reconnections
    pub reconnect_max: Duration,
}

impl Default for MqttSettings {
    fn default() -> Self {
        MqttSettings {
            keep_alive: Duration::from_secs(60),
            max_packet_size: 64 * 1024,
            reconnect_min: Duration::from_secs(1),
            reconnect_max: Duration::from_secs(60),
        }
    }
}

/// MQTT session to open, given by the adaptor.
///
/// The session uses a clean session, and the subscriptions are renewed on every reconnection.
#[derive(Clone, PartialEq)]
pub struct MqttSession {
    /// Broker target, e.g. `mqtts://broker:8883`.
    /// TLS is used for the `mqtts` scheme or any scheme handled as SSL by ProSA (`ssl`, `mqtt+ssl`, or an SSL configuration).
    pub target: TargetSetting,
    /// Client identifier, unique per broker
    pub client_id: String,
    /// Username to log in with
    pub username: Option<String>,
    /// Password to log in with, sent only with a username
    pub password: Option<String>,
    /// Topic filters to subscribe to, with their requested QoS. Filters can use the `+` and `#` MQTT wildcards.
    /// Messages on these topics go to [`FetcherAdaptor::process_mqtt_message`](crate::adaptor::FetcherAdaptor::process_mqtt_message).
    pub subscriptions: Vec<(String, QoS)>,
}

impl MqttSession {
    /// Target to connect to, with the `mqtts` scheme mapped to ProSA's SSL scheme
    fn broker_target(&self) -> TargetSetting {
        let mut target = self.target.clone();
        if target.url.scheme() == "mqtts" {
            let _ = target.url.set_scheme("mqtt+ssl");
        }
        target
    }
}

impl fmt::Debug for MqttSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MqttSession")
            .field("target", &self.target)
            .field("client_id", &self.client_id)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("subscriptions", &self.subscriptions)
            .finish()
    }
}

/// MQTT session state change, given to the adaptor
#[derive(Debug)]
pub enum MqttEvent<M>
where
    M: Send,
{
    /// The broker accepted the connection and acknowledged the subscriptions.
    /// Lists the topic filters it refused.
    Connected {
        /// Topic filters refused by the broker
        rejected_subscriptions: Vec<String>,
    },
    /// The connection failed or was lost. The session reconnects with a backoff.
    /// Only the first failure is reported until the session connects again.
    Disconnected(FetcherError<M>),
    /// The broker refused the connection (bad credentials, not authorized, rejected client id or protocol).
    /// The session stops; return a new [`MqttSession`] to connect again.
    Refused(ConnectReturnCode),
}

pub(crate) enum WorkerEvent<M>
where
    M: Send,
{
    Message { topic: String, payload: Bytes },
    State(MqttEvent<M>),
}

/// Worker task running an MQTT session, aborted on drop
pub(crate) struct MqttWorker<M>
where
    M: Send,
{
    session: MqttSession,
    pub(crate) events_rx: mpsc::Receiver<WorkerEvent<M>>,
    stop_tx: Option<oneshot::Sender<()>>,
    task: AbortOnDropJoinHandle<()>,
}

impl<M> MqttWorker<M>
where
    M: Send + 'static,
{
    pub(crate) fn spawn(session: MqttSession, settings: &MqttSettings, timeout: Duration) -> Self {
        let (events_tx, events_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (stop_tx, stop_rx) = oneshot::channel();
        let client = Client {
            target: session.broker_target(),
            session: session.clone(),
            settings: settings.clone(),
            timeout,
            events_tx,
        };
        Self {
            session,
            events_rx,
            stop_tx: Some(stop_tx),
            task: AbortOnDropJoinHandle(tokio::spawn(client.run(stop_rx))),
        }
    }

    pub(crate) fn session(&self) -> &MqttSession {
        &self.session
    }

    /// Disconnect from the broker, and abort the worker if it doesn't stop within `timeout`
    pub(crate) async fn close(mut self, timeout: Duration) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        let _ = time::timeout(timeout, &mut self.task.0).await;
    }
}

enum ConnectError<M>
where
    M: Send,
{
    Refused(ConnectReturnCode),
    Failed(FetcherError<M>),
}

impl<M: Send> From<FetcherError<M>> for ConnectError<M> {
    fn from(error: FetcherError<M>) -> Self {
        ConnectError::Failed(error)
    }
}

struct Client<M>
where
    M: Send,
{
    target: TargetSetting,
    session: MqttSession,
    settings: MqttSettings,
    timeout: Duration,
    events_tx: mpsc::Sender<WorkerEvent<M>>,
}

impl<M> Client<M>
where
    M: Send + 'static,
{
    fn keep_alive_secs(&self) -> u16 {
        u16::try_from(self.settings.keep_alive.as_secs()).unwrap_or(u16::MAX)
    }

    fn timeout_error(&self, stage: &str) -> FetcherError<M> {
        FetcherError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "MQTT {stage} timeout after {:?} with `{}`",
                self.timeout, self.target
            ),
        ))
    }

    fn eof_error(&self) -> FetcherError<M> {
        FetcherError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("MQTT broker `{}` closed the connection", self.target),
        ))
    }

    async fn run(self, mut stop_rx: oneshot::Receiver<()>) {
        let mut backoff = self.settings.reconnect_min;
        let mut reported_down = false;
        loop {
            let attempt = tokio::select! {
                _ = &mut stop_rx => return,
                attempt = self.connect() => attempt,
            };
            let error = match attempt {
                Ok((stream, buf)) => {
                    let mut connected = false;
                    let end = self.serve(stream, buf, &mut stop_rx, &mut connected).await;
                    if connected {
                        backoff = self.settings.reconnect_min;
                        reported_down = false;
                    }
                    match end {
                        Some(error) => error,
                        None => return,
                    }
                }
                Err(ConnectError::Refused(code)) => {
                    warn!(broker = %self.target, client_id = self.session.client_id, ?code, "MQTT broker refused the connection; session stopped");
                    self.send(WorkerEvent::State(MqttEvent::Refused(code)), &mut stop_rx)
                        .await;
                    return;
                }
                Err(ConnectError::Failed(error)) => error,
            };

            warn!(broker = %self.target, %error, "MQTT connection failed; reconnect in {backoff:?}");
            if !reported_down {
                reported_down = true;
                if !self
                    .send(
                        WorkerEvent::State(MqttEvent::Disconnected(error)),
                        &mut stop_rx,
                    )
                    .await
                {
                    return;
                }
            }
            tokio::select! {
                _ = &mut stop_rx => return,
                _ = time::sleep(backoff) => {}
            }
            backoff = backoff
                .checked_mul(2)
                .unwrap_or(self.settings.reconnect_max)
                .min(self.settings.reconnect_max)
                .max(self.settings.reconnect_min);
        }
    }

    /// Send an event to the processor. Return `false` if the session must stop.
    async fn send(&self, event: WorkerEvent<M>, stop_rx: &mut oneshot::Receiver<()>) -> bool {
        tokio::select! {
            _ = stop_rx => false,
            sent = self.events_tx.send(event) => sent.is_ok(),
        }
    }

    async fn write(&self, stream: &mut Stream, packet: Packet) -> Result<(), FetcherError<M>> {
        let mut bytes = BytesMut::new();
        packet
            .write(&mut bytes, self.settings.max_packet_size)
            .map_err(MqttError::from)?;
        time::timeout(self.timeout, async {
            stream.write_all(&bytes).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| self.timeout_error("write"))??;
        Ok(())
    }

    fn next_packet(&self, buf: &mut BytesMut) -> Result<Option<Packet>, FetcherError<M>> {
        match Packet::read(buf, self.settings.max_packet_size) {
            Ok(packet) => Ok(Some(packet)),
            Err(MqttCodecError::InsufficientBytes(_)) => Ok(None),
            Err(error) => Err(MqttError::from(error).into()),
        }
    }

    /// Connect to the broker, log in, and send the subscriptions
    async fn connect(&self) -> Result<(Stream, BytesMut), ConnectError<M>> {
        let mut stream = self.target.connect().await.map_err(FetcherError::Io)?;
        let mut connect = Connect::new(self.session.client_id.clone());
        connect.keep_alive = self.keep_alive_secs();
        connect.clean_session = true;
        connect.login = self.session.username.as_ref().map(|username| {
            Login::new(
                username.clone(),
                self.session.password.clone().unwrap_or_default(),
            )
        });
        self.write(&mut stream, Packet::Connect(connect)).await?;

        let mut buf = BytesMut::with_capacity(READ_CHUNK_SIZE);
        let connack = time::timeout(self.timeout, async {
            loop {
                if let Some(packet) = self.next_packet(&mut buf)? {
                    return Ok(packet);
                }
                buf.reserve(READ_CHUNK_SIZE);
                if stream.read_buf(&mut buf).await? == 0 {
                    return Err(self.eof_error());
                }
            }
        })
        .await
        .map_err(|_| self.timeout_error("CONNACK"))??;

        match connack {
            Packet::ConnAck(ConnAck {
                code: ConnectReturnCode::Success,
                ..
            }) => {}
            Packet::ConnAck(ConnAck {
                code: ConnectReturnCode::ServiceUnavailable,
                ..
            }) => {
                return Err(FetcherError::Io(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("MQTT broker `{}` is unavailable", self.target),
                ))
                .into());
            }
            Packet::ConnAck(ConnAck { code, .. }) => return Err(ConnectError::Refused(code)),
            _ => return Err(FetcherError::from(MqttError::UnexpectedPacket("CONNACK")).into()),
        }

        if !self.session.subscriptions.is_empty() {
            let mut subscribe = Subscribe::new_many(
                self.session
                    .subscriptions
                    .iter()
                    .map(|(topic, qos)| SubscribeFilter::new(topic.clone(), *qos)),
            );
            subscribe.pkid = 1;
            self.write(&mut stream, Packet::Subscribe(subscribe))
                .await?;
        }

        Ok((stream, buf))
    }

    /// Serve a connected session. Return `None` when the session stops, or the error that closed the connection.
    /// `connected` is set once the subscriptions are acknowledged.
    async fn serve(
        &self,
        mut stream: Stream,
        mut buf: BytesMut,
        stop_rx: &mut oneshot::Receiver<()>,
        connected: &mut bool,
    ) -> Option<FetcherError<M>> {
        let keep_alive = Duration::from_secs(self.keep_alive_secs().into());
        let mut ping_interval = time::interval_at(
            time::Instant::now() + keep_alive,
            keep_alive.max(Duration::from_secs(1)),
        );
        ping_interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        let mut ping_pending = false;
        let (mut suback_deadline, mut outbox) = if self.session.subscriptions.is_empty() {
            (
                None,
                Some(WorkerEvent::State(MqttEvent::Connected {
                    rejected_subscriptions: Vec::new(),
                })),
            )
        } else {
            (Some(time::Instant::now() + self.timeout), None)
        };

        loop {
            // Parse buffered packets until one produces an event for the processor
            while outbox.is_none() {
                let packet = match self.next_packet(&mut buf) {
                    Ok(Some(packet)) => packet,
                    Ok(None) => break,
                    Err(error) => return Some(error),
                };
                let ack = match packet {
                    Packet::Publish(publish) => {
                        outbox = Some(WorkerEvent::Message {
                            topic: publish.topic,
                            payload: publish.payload,
                        });
                        match publish.qos {
                            QoS::AtMostOnce => None,
                            QoS::AtLeastOnce => Some(Packet::PubAck(PubAck::new(publish.pkid))),
                            QoS::ExactlyOnce => Some(Packet::PubRec(PubRec::new(publish.pkid))),
                        }
                    }
                    Packet::PubRel(pubrel) => Some(Packet::PubComp(PubComp::new(pubrel.pkid))),
                    Packet::PingResp => {
                        ping_pending = false;
                        None
                    }
                    Packet::SubAck(suback) => {
                        suback_deadline = None;
                        let rejected_subscriptions: Vec<String> = self
                            .session
                            .subscriptions
                            .iter()
                            .zip(&suback.return_codes)
                            .filter(|(_, code)| matches!(code, SubscribeReasonCode::Failure))
                            .map(|((topic, _), _)| topic.clone())
                            .collect();
                        if !rejected_subscriptions.is_empty() {
                            warn!(broker = %self.target, ?rejected_subscriptions, "MQTT broker rejected subscriptions");
                        }
                        outbox = Some(WorkerEvent::State(MqttEvent::Connected {
                            rejected_subscriptions,
                        }));
                        None
                    }
                    packet => {
                        debug!(broker = %self.target, ?packet, "Ignore MQTT packet");
                        None
                    }
                };
                if let Some(ack) = ack
                    && let Err(error) = self.write(&mut stream, ack).await
                {
                    return Some(error);
                }
            }

            buf.reserve(READ_CHUNK_SIZE);
            tokio::select! {
                _ = &mut *stop_rx => {
                    if let Err(error) = self.write(&mut stream, Packet::Disconnect).await {
                        debug!(broker = %self.target, %error, "Can't send MQTT DISCONNECT");
                    }
                    return None;
                }
                permit = self.events_tx.reserve(), if outbox.is_some() => match permit {
                    Ok(permit) => {
                        if let Some(event) = outbox.take() {
                            if matches!(event, WorkerEvent::State(MqttEvent::Connected { .. })) {
                                info!(broker = %self.target, client_id = self.session.client_id, "MQTT connected");
                                *connected = true;
                            }
                            permit.send(event);
                        }
                    }
                    Err(_) => return None,
                },
                read = stream.read_buf(&mut buf), if outbox.is_none() => match read {
                    Ok(0) => return Some(self.eof_error()),
                    Ok(_) => {}
                    Err(error) => return Some(FetcherError::Io(error)),
                },
                _ = ping_interval.tick(), if !keep_alive.is_zero() => {
                    if ping_pending {
                        return Some(self.timeout_error("PINGRESP"));
                    }
                    if let Err(error) = self.write(&mut stream, Packet::PingReq).await {
                        return Some(error);
                    }
                    ping_pending = true;
                }
                _ = time::sleep_until(suback_deadline.unwrap_or_else(time::Instant::now)), if suback_deadline.is_some() => {
                    return Some(self.timeout_error("SUBACK"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adaptor::FetcherAdaptor,
        proc::{FetchAction, FetcherProc, FetcherSettings, TimeRange},
    };
    use chrono::Local;
    use http::{Request, Response};
    use http_body_util::{BodyExt as _, Empty, combinators::BoxBody};
    use hyper::body::Incoming;
    use prosa::core::{
        adaptor::Adaptor,
        main::{MainProc, MainRunnable as _},
        proc::ProcConfig as _,
        settings::settings,
    };
    use prosa_utils::msg::simple_string_tvf::SimpleStringTvf;
    use rumqttc::mqttbytes::v4::{Publish, SubAck};
    use std::{
        convert::Infallible,
        net::SocketAddr,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };
    use tokio::net::{TcpListener, TcpStream};
    use url::Url;

    const BROKER_MAX_PACKET_SIZE: usize = 1024 * 1024;
    const TOPIC: &str = "/open/account/SN/quota";

    struct BrokerConnection {
        stream: TcpStream,
        buf: BytesMut,
    }

    impl BrokerConnection {
        async fn accept(listener: &TcpListener) -> Self {
            let (stream, _) = listener.accept().await.unwrap();
            Self {
                stream,
                buf: BytesMut::new(),
            }
        }

        async fn read(&mut self) -> Packet {
            loop {
                match Packet::read(&mut self.buf, BROKER_MAX_PACKET_SIZE) {
                    Ok(packet) => return packet,
                    Err(MqttCodecError::InsufficientBytes(_)) => {}
                    Err(error) => panic!("broker can't decode the client packet: {error}"),
                }
                let read = self.stream.read_buf(&mut self.buf).await.unwrap();
                assert_ne!(0, read, "client closed the connection");
            }
        }

        async fn write(&mut self, packet: Packet) {
            let mut bytes = BytesMut::new();
            packet.write(&mut bytes, BROKER_MAX_PACKET_SIZE).unwrap();
            self.stream.write_all(&bytes).await.unwrap();
        }

        async fn handshake(&mut self, code: ConnectReturnCode) -> Connect {
            let Packet::Connect(connect) = self.read().await else {
                panic!("broker expects CONNECT");
            };
            self.write(Packet::ConnAck(ConnAck::new(code, false))).await;
            connect
        }

        async fn subscribe(&mut self) -> Subscribe {
            let Packet::Subscribe(subscribe) = self.read().await else {
                panic!("broker expects SUBSCRIBE");
            };
            let codes = subscribe
                .filters
                .iter()
                .map(|filter| SubscribeReasonCode::Success(filter.qos))
                .collect();
            self.write(Packet::SubAck(SubAck::new(subscribe.pkid, codes)))
                .await;
            subscribe
        }

        async fn publish(&mut self, pkid: u16, payload: Vec<u8>) {
            let mut publish = Publish::new(TOPIC, QoS::AtLeastOnce, payload);
            publish.pkid = pkid;
            self.write(Packet::Publish(publish)).await;
        }
    }

    fn session(addr: SocketAddr, password: &str) -> MqttSession {
        MqttSession {
            target: TargetSetting::from(Url::parse(&format!("mqtt://{addr}")).unwrap()),
            client_id: "account_fetcher".into(),
            username: Some("account".into()),
            password: Some(password.into()),
            subscriptions: vec![(TOPIC.into(), QoS::AtLeastOnce)],
        }
    }

    fn mqtt_settings() -> MqttSettings {
        MqttSettings {
            keep_alive: Duration::from_secs(60),
            max_packet_size: 1024,
            reconnect_min: Duration::from_millis(20),
            reconnect_max: Duration::from_millis(100),
        }
    }

    async fn next_state(worker: &mut MqttWorker<SimpleStringTvf>) -> MqttEvent<SimpleStringTvf> {
        match worker.events_rx.recv().await {
            Some(WorkerEvent::State(event)) => event,
            Some(WorkerEvent::Message { topic, .. }) => panic!("unexpected message on {topic}"),
            None => panic!("MQTT worker stopped"),
        }
    }

    #[tokio::test]
    async fn connects_mqtts_brokers_over_tls() {
        time::timeout(Duration::from_secs(1), async {
            let mut tls_session = session("127.0.0.1:8883".parse().unwrap(), "secret");
            tls_session.target =
                TargetSetting::from(Url::parse("mqtts://mqtt.example.com:8883").unwrap());
            let target = tls_session.broker_target();
            assert!(target.is_ssl());
            assert_eq!(Some(8883), target.url.port());
            assert!(
                !session("127.0.0.1:1883".parse().unwrap(), "secret")
                    .broker_target()
                    .is_ssl()
            );
            assert!(!format!("{tls_session:?}").contains("secret"));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn delivers_subscribed_messages() {
        time::timeout(Duration::from_secs(2), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut worker = MqttWorker::<SimpleStringTvf>::spawn(
                session(addr, "secret"),
                &mqtt_settings(),
                Duration::from_secs(1),
            );

            let mut broker = BrokerConnection::accept(&listener).await;
            let connect = broker.handshake(ConnectReturnCode::Success).await;
            assert_eq!("account_fetcher", connect.client_id);
            assert!(connect.clean_session);
            assert_eq!(60, connect.keep_alive);
            assert_eq!(Some(Login::new("account", "secret")), connect.login);
            let subscribe = broker.subscribe().await;
            assert_eq!(
                vec![SubscribeFilter::new(TOPIC.into(), QoS::AtLeastOnce)],
                subscribe.filters
            );
            assert!(matches!(
                next_state(&mut worker).await,
                MqttEvent::Connected { rejected_subscriptions } if rejected_subscriptions.is_empty()
            ));

            broker
                .publish(7, br#"{"params":{"powGetPv":12.5}}"#.to_vec())
                .await;
            match worker.events_rx.recv().await {
                Some(WorkerEvent::Message { topic, payload }) => {
                    assert_eq!(TOPIC, topic);
                    assert_eq!(
                        Bytes::from_static(br#"{"params":{"powGetPv":12.5}}"#),
                        payload
                    );
                }
                _ => panic!("MQTT worker should deliver the message"),
            }
            assert_eq!(Packet::PubAck(PubAck::new(7)), broker.read().await);

            worker.close(Duration::from_secs(1)).await;
            assert_eq!(Packet::Disconnect, broker.read().await);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn reconnects_after_oversized_packet() {
        time::timeout(Duration::from_secs(2), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut worker = MqttWorker::<SimpleStringTvf>::spawn(
                session(addr, "secret"),
                &mqtt_settings(),
                Duration::from_secs(1),
            );

            let mut broker = BrokerConnection::accept(&listener).await;
            broker.handshake(ConnectReturnCode::Success).await;
            broker.subscribe().await;
            assert!(matches!(
                next_state(&mut worker).await,
                MqttEvent::Connected { .. }
            ));

            broker.publish(1, vec![b'x'; 2048]).await;
            assert!(matches!(
                next_state(&mut worker).await,
                MqttEvent::Disconnected(FetcherError::Mqtt(MqttError::Codec(
                    MqttCodecError::PayloadSizeLimitExceeded(_)
                )))
            ));

            let mut broker = BrokerConnection::accept(&listener).await;
            broker.handshake(ConnectReturnCode::Success).await;
            broker.subscribe().await;
            assert!(matches!(
                next_state(&mut worker).await,
                MqttEvent::Connected { .. }
            ));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn resubscribes_after_broker_restart() {
        time::timeout(Duration::from_secs(2), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut worker = MqttWorker::<SimpleStringTvf>::spawn(
                session(addr, "secret"),
                &mqtt_settings(),
                Duration::from_secs(1),
            );

            let mut broker = BrokerConnection::accept(&listener).await;
            broker.handshake(ConnectReturnCode::Success).await;
            broker.subscribe().await;
            assert!(matches!(
                next_state(&mut worker).await,
                MqttEvent::Connected { .. }
            ));

            drop(broker);
            assert!(matches!(
                next_state(&mut worker).await,
                MqttEvent::Disconnected(FetcherError::Io(_))
            ));
            // The restarting broker closes the reconnections before answering
            for _ in 0..2 {
                drop(BrokerConnection::accept(&listener).await);
            }

            let mut broker = BrokerConnection::accept(&listener).await;
            broker.handshake(ConnectReturnCode::Success).await;
            let subscribe = broker.subscribe().await;
            assert_eq!(TOPIC, subscribe.filters[0].path);
            // Failed reconnections are not reported again
            assert!(matches!(
                next_state(&mut worker).await,
                MqttEvent::Connected { .. }
            ));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn backs_off_when_broker_drops_subscriptions() {
        time::timeout(Duration::from_secs(2), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut worker = MqttWorker::<SimpleStringTvf>::spawn(
                session(addr, "secret"),
                &mqtt_settings(),
                Duration::from_secs(1),
            );

            // The broker accepts the login but closes the connection on SUBSCRIBE
            let mut first_drop = None;
            for _ in 0..4 {
                let mut broker = BrokerConnection::accept(&listener).await;
                broker.handshake(ConnectReturnCode::Success).await;
                let Packet::Subscribe(_) = broker.read().await else {
                    panic!("broker expects SUBSCRIBE");
                };
                first_drop.get_or_insert_with(time::Instant::now);
            }
            // 20 + 40 + 80 ms of backoff between the 4 attempts, 60 ms if it was reset by every CONNACK
            assert!(first_drop.unwrap().elapsed() >= Duration::from_millis(120));

            let mut broker = BrokerConnection::accept(&listener).await;
            broker.handshake(ConnectReturnCode::Success).await;
            broker.subscribe().await;
            assert!(matches!(
                next_state(&mut worker).await,
                MqttEvent::Disconnected(_)
            ));
            // The failed attempts after the first one are not reported
            assert!(matches!(
                next_state(&mut worker).await,
                MqttEvent::Connected { .. }
            ));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn stops_session_when_broker_refuses_credentials() {
        time::timeout(Duration::from_secs(2), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut worker = MqttWorker::<SimpleStringTvf>::spawn(
                session(addr, "expired"),
                &mqtt_settings(),
                Duration::from_secs(1),
            );

            let mut broker = BrokerConnection::accept(&listener).await;
            broker
                .handshake(ConnectReturnCode::BadUserNamePassword)
                .await;
            assert!(matches!(
                next_state(&mut worker).await,
                MqttEvent::Refused(ConnectReturnCode::BadUserNamePassword)
            ));
            assert!(worker.events_rx.recv().await.is_none());
            assert!(
                time::timeout(Duration::from_millis(200), listener.accept())
                    .await
                    .is_err(),
                "a refused session must not reconnect"
            );
        })
        .await
        .unwrap();
    }

    #[settings]
    #[derive(Default, Debug, Serialize)]
    struct RuntimeTestSettings {}

    fn get_request() -> Result<Request<BoxBody<Bytes, Infallible>>, FetcherError<SimpleStringTvf>> {
        Ok(Request::builder()
            .uri("/certification")
            .body(Empty::<Bytes>::new().boxed())?)
    }

    /// HTTP server answering `200 OK` to every request
    async fn http_server(listener: TcpListener) {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = BytesMut::new();
                loop {
                    if let Some(end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
                        let _ = buf.split_to(end + 4);
                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .unwrap();
                    } else if stream.read_buf(&mut buf).await.unwrap_or(0) == 0 {
                        return;
                    }
                }
            });
        }
    }

    async fn run_fetcher<A>(name: &str, settings: FetcherSettings, done: impl Future<Output = ()>)
    where
        A: Adaptor + FetcherAdaptor<SimpleStringTvf> + Send + 'static,
    {
        let runtime_settings = RuntimeTestSettings::default();
        let (bus, main) = MainProc::<SimpleStringTvf>::create(&runtime_settings, Some(1));
        let main_task = tokio::spawn(main.run());
        let mut processor =
            FetcherProc::<SimpleStringTvf>::create(1, name.into(), bus.clone(), settings);
        let processor_task = tokio::spawn(async move {
            <FetcherProc<SimpleStringTvf> as prosa::core::proc::Proc<A>>::internal_run(
                &mut processor,
            )
            .await
            .map_err(|error| error.to_string())
        });
        done.await;
        bus.stop("MQTT fetcher test complete".into()).await.unwrap();
        let _ = processor_task.await.unwrap();
        main_task.await.unwrap();
    }

    static REFRESH_BROKER: Mutex<Option<SocketAddr>> = Mutex::new(None);
    static REFRESH_HTTP_RESPONSES: AtomicUsize = AtomicUsize::new(0);
    static REFRESH_MESSAGES: AtomicUsize = AtomicUsize::new(0);

    #[derive(Default)]
    struct RefreshAdaptor {
        started: bool,
    }

    impl Adaptor for RefreshAdaptor {
        fn terminate(&self) {}
    }

    impl FetcherAdaptor<SimpleStringTvf> for RefreshAdaptor {
        fn new(
            _proc: &FetcherProc<SimpleStringTvf>,
        ) -> Result<Self, FetcherError<SimpleStringTvf>> {
            Ok(Self::default())
        }

        fn fetch(&mut self) -> Result<FetchAction<SimpleStringTvf>, FetcherError<SimpleStringTvf>> {
            Ok(if std::mem::replace(&mut self.started, true) {
                FetchAction::None
            } else {
                FetchAction::Http
            })
        }

        fn create_http_request(
            &self,
            _request_builder: http::request::Builder,
        ) -> Result<Request<BoxBody<Bytes, Infallible>>, FetcherError<SimpleStringTvf>> {
            get_request()
        }

        async fn process_http_response(
            &mut self,
            response: Result<Response<Incoming>, FetcherError<SimpleStringTvf>>,
        ) -> Result<FetchAction<SimpleStringTvf>, FetcherError<SimpleStringTvf>> {
            response?;
            let certification = REFRESH_HTTP_RESPONSES.fetch_add(1, Ordering::SeqCst) + 1;
            let broker = REFRESH_BROKER.lock().unwrap().expect("test broker address");
            Ok(FetchAction::Mqtt(Box::new(session(
                broker,
                &format!("password{certification}"),
            ))))
        }

        fn process_mqtt_message(
            &mut self,
            topic: &str,
            _payload: Bytes,
        ) -> Result<FetchAction<SimpleStringTvf>, FetcherError<SimpleStringTvf>> {
            assert_eq!(TOPIC, topic);
            REFRESH_MESSAGES.fetch_add(1, Ordering::SeqCst);
            Ok(FetchAction::None)
        }

        fn process_mqtt_event(
            &mut self,
            event: MqttEvent<SimpleStringTvf>,
        ) -> Result<FetchAction<SimpleStringTvf>, FetcherError<SimpleStringTvf>> {
            Ok(match event {
                MqttEvent::Refused(_) => FetchAction::Http,
                _ => FetchAction::None,
            })
        }
    }

    #[tokio::test]
    async fn refreshes_session_after_refusal_and_disconnects_on_shutdown() {
        time::timeout(Duration::from_secs(3), async {
            let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let http_addr = http_listener.local_addr().unwrap();
            let http_task = tokio::spawn(http_server(http_listener));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            *REFRESH_BROKER.lock().unwrap() = Some(listener.local_addr().unwrap());

            let broker_task = tokio::spawn(async move {
                let mut broker = BrokerConnection::accept(&listener).await;
                let connect = broker.handshake(ConnectReturnCode::NotAuthorized).await;
                assert_eq!(Some(Login::new("account", "password1")), connect.login);

                let mut broker = BrokerConnection::accept(&listener).await;
                let connect = broker.handshake(ConnectReturnCode::Success).await;
                assert_eq!(Some(Login::new("account", "password2")), connect.login);
                broker.subscribe().await;
                broker.publish(1, br#"{"params":{}}"#.to_vec()).await;
                assert_eq!(Packet::PubAck(PubAck::new(1)), broker.read().await);
                assert_eq!(Packet::Disconnect, broker.read().await);
            });

            let mut settings = FetcherSettings::new(
                TargetSetting::from(Url::parse(&format!("http://{http_addr}")).unwrap()),
                String::new(),
                false,
                Duration::from_millis(50),
                Duration::from_millis(500),
            );
            settings.mqtt = mqtt_settings();
            run_fetcher::<RefreshAdaptor>("MQTT_REFRESH_FETCHER", settings, async {
                while REFRESH_MESSAGES.load(Ordering::SeqCst) == 0 {
                    time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await;

            broker_task.await.unwrap();
            assert_eq!(2, REFRESH_HTTP_RESPONSES.load(Ordering::SeqCst));
            http_task.abort();
        })
        .await
        .unwrap();
    }

    static ACTIVE_BROKER: Mutex<Option<SocketAddr>> = Mutex::new(None);
    static ACTIVE_PERIOD_ENDED: AtomicBool = AtomicBool::new(false);

    #[derive(Default)]
    struct ActivePeriodAdaptor {
        started: bool,
    }

    impl Adaptor for ActivePeriodAdaptor {
        fn terminate(&self) {}
    }

    impl FetcherAdaptor<SimpleStringTvf> for ActivePeriodAdaptor {
        fn new(
            _proc: &FetcherProc<SimpleStringTvf>,
        ) -> Result<Self, FetcherError<SimpleStringTvf>> {
            Ok(Self::default())
        }

        fn fetch(&mut self) -> Result<FetchAction<SimpleStringTvf>, FetcherError<SimpleStringTvf>> {
            if std::mem::replace(&mut self.started, true) {
                return Ok(FetchAction::None);
            }
            let broker = ACTIVE_BROKER.lock().unwrap().expect("test broker address");
            Ok(FetchAction::Mqtt(Box::new(session(broker, "secret"))))
        }

        fn end_active_period(&mut self) {
            ACTIVE_PERIOD_ENDED.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn closes_session_when_active_period_ends() {
        time::timeout(Duration::from_secs(3), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            *ACTIVE_BROKER.lock().unwrap() = Some(listener.local_addr().unwrap());
            let broker_task = tokio::spawn(async move {
                let mut broker = BrokerConnection::accept(&listener).await;
                broker.handshake(ConnectReturnCode::Success).await;
                broker.subscribe().await;
                assert_eq!(Packet::Disconnect, broker.read().await);
            });

            let now = Local::now().time();
            let mut settings = FetcherSettings::new(
                TargetSetting::from(Url::parse("http://127.0.0.1:9").unwrap()),
                String::new(),
                false,
                Duration::from_millis(50),
                Duration::from_millis(500),
            );
            settings.active_time_range = Some(TimeRange {
                start: now - chrono::Duration::minutes(1),
                end: now + chrono::Duration::milliseconds(500),
            });
            settings.mqtt = mqtt_settings();
            run_fetcher::<ActivePeriodAdaptor>("MQTT_ACTIVE_FETCHER", settings, async {
                broker_task.await.unwrap();
                while !ACTIVE_PERIOD_ENDED.load(Ordering::SeqCst) {
                    time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await;
        })
        .await
        .unwrap();
    }
}
