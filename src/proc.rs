use std::{convert::Infallible, io, time::Duration};

use base64::{
    DecodeError, Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use chrono::{Local, NaiveTime};
use http::Response;
use http_body_util::combinators::BoxBody;
use hyper::{
    Request,
    body::{Bytes, Incoming},
    client::conn::{http1, http2},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use prosa::{
    core::{
        adaptor::Adaptor,
        error::ProcError,
        msg::{InternalMsg, Msg, RequestMsg},
        proc::{Proc, ProcBusParam as _, proc, proc_settings},
    },
    io::stream::TargetSetting,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    sync::{mpsc, watch},
    time,
};
use tracing::{debug, info, warn};

use crate::adaptor::FetcherAdaptor;

#[derive(Debug, Error)]
/// ProSA service error when the service can't respond correctly to a request
pub enum FetcherError<M>
where
    M: std::marker::Send,
{
    /// IO error
    #[error("IO error during the fetch `{0}`")]
    Io(#[from] io::Error),
    /// Hyper error
    #[error("Hyper error during the fetch `{0:?}` from `{1}`")]
    Hyper(hyper::Error, String),
    /// HTTP error
    #[error("HTTP error on object parsing `{0}`")]
    Http(#[from] http::Error),
    /// Queue error
    #[error("Fetcher communication error `{0}`")]
    Queue(#[from] watch::error::SendError<FetchAction<M>>),
    /// HTTP queue error
    #[error("No HTTP task available to process the message `{0}`")]
    HttpQueue(Box<mpsc::error::SendError<http::Request<BoxBody<Bytes, Infallible>>>>),
    /// Base64 decode error
    #[error("Can't decode Base64 data `{0}`")]
    B64Decode(#[from] DecodeError),
    /// Other error
    #[error("Fetcher other error `{0}`")]
    Other(String),
}

impl<M> From<mpsc::error::SendError<http::Request<BoxBody<Bytes, Infallible>>>> for FetcherError<M>
where
    M: std::marker::Send,
{
    fn from(error: mpsc::error::SendError<http::Request<BoxBody<Bytes, Infallible>>>) -> Self {
        FetcherError::<M>::HttpQueue(Box::new(error))
    }
}

impl<M> ProcError for FetcherError<M>
where
    M: 'static + std::fmt::Debug + std::marker::Send,
{
    fn recoverable(&self) -> bool {
        match self {
            FetcherError::Io(error) => error.recoverable(),
            FetcherError::Hyper(_error, _addr) => true,
            FetcherError::Http(_error) => true,
            FetcherError::Queue(_send_error) => false,
            FetcherError::HttpQueue(_send_error) => false,
            FetcherError::B64Decode(_decode_error) => false,
            FetcherError::Other(_) => false,
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize, Copy, Clone)]
pub enum AuthMethod {
    /// Don't use the credential in URL to auth. Let the adaptor do the authentication..
    None,
    #[default]
    /// Basic authentication method with credential provided from URL
    Basic,
}

#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct TimeRange {
    /// Start period hour
    pub start: NaiveTime,
    /// End period hour
    pub end: NaiveTime,
}

impl TimeRange {
    // Méthode pour vérifier si une heure donnée est dans la plage
    pub fn contains(&self, time: &NaiveTime) -> bool {
        if self.start <= self.end {
            time >= &self.start && time <= &self.end
        } else {
            time >= &self.start || time <= &self.end
        }
    }
}

/// Settings for Fetcher processor
#[proc_settings]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FetcherSettings {
    /// Target settings to connect to the remote system
    target: Option<TargetSetting>,
    /// Remote service to call in order to fetch information from remote system
    service_name: Option<String>,
    /// Authentication method use when a user:password is provide in the URL to authenticate to the remote
    #[serde(default)]
    pub auth_method: AuthMethod,
    /// Period where the remote system need to be fetch
    #[serde(default = "FetcherSettings::get_default_period")]
    period: Duration,
    /// Timeout duration for every fetch
    #[serde(default = "FetcherSettings::get_default_timeout")]
    timeout: Duration,
    /// Hour time range when the fetcher execute
    pub(crate) active_time_range: Option<TimeRange>,
    #[serde(default)]
    title_case_headers: bool,
}

impl FetcherSettings {
    fn get_default_period() -> Duration {
        Duration::from_secs(60)
    }

    fn get_default_timeout() -> Duration {
        Duration::from_secs(10)
    }

    /// Create a new Fetcher settings
    pub fn new(
        target: TargetSetting,
        service_name: String,
        auth_method: AuthMethod,
        period: Duration,
        timeout: Duration,
    ) -> FetcherSettings {
        FetcherSettings {
            target: Some(target),
            service_name: Some(service_name),
            auth_method,
            period,
            timeout,
            ..Default::default()
        }
    }

    /// Get the username for login
    pub fn username(&self) -> Option<&str> {
        self.target.as_ref().map(|t| t.url.username())
    }

    /// Getter of the URL password (decode from Base64Url)
    pub fn password(&self) -> Result<Option<Vec<u8>>, DecodeError> {
        if let Some(password) = self.target.as_ref().and_then(|t| t.url.password()) {
            Ok(Some(URL_SAFE.decode(password.replace("%3D", "="))?))
        } else {
            Ok(None)
        }
    }

    /// Method to get a challenged password to authenticate.
    /// mac is the HMac function to use for your challenge.
    pub fn challenge_password<H, M>(
        &self,
        challenge: &[u8],
    ) -> Result<Option<bytes::Bytes>, FetcherError<M>>
    where
        H: hmac::Mac + hmac::digest::KeyInit,
        M: Send,
    {
        if let Some(password) = self.target.as_ref().and_then(|t| t.url.password()) {
            let binary_password = URL_SAFE.decode(password.replace("%3D", "="))?;
            let mut mac =
                <H as hmac::digest::KeyInit>::new_from_slice(&binary_password).map_err(|e| {
                    FetcherError::Other(format!("Crypto error on password challenge {e}"))
                })?;
            mac.update(challenge);
            return Ok(Some(bytes::Bytes::copy_from_slice(
                &mac.finalize().into_bytes(),
            )));
        }

        Ok(None)
    }

    /// Method to know if the fetcher is active depending of the time of the day.
    /// It only return false if an `active_time_range` is set and the current time is not in range
    pub fn is_active(&self) -> bool {
        if let Some(active_time_range) = self.active_time_range {
            active_time_range.contains(&Local::now().time())
        } else {
            true
        }
    }

    /// Getter of an HTTP1 context
    pub fn get_http1_ctx(&self) -> http1::Builder {
        let mut http1_ctx = http1::Builder::new();

        if self.title_case_headers {
            // Set HTTP1 context for old HTTP server
            http1_ctx.title_case_headers(true);
        }

        http1_ctx
    }
}

#[proc_settings]
impl Default for FetcherSettings {
    fn default() -> Self {
        FetcherSettings {
            target: None,
            service_name: None,
            auth_method: AuthMethod::default(),
            period: Self::get_default_period(),
            timeout: Self::get_default_timeout(),
            active_time_range: None,
            title_case_headers: false,
        }
    }
}

/// Enum that describe what action should be done everytime
#[derive(Debug)]
pub enum FetchAction<M>
where
    M: std::marker::Send,
{
    /// No further action
    None,
    /// Send an HTTP request message
    Http,
    /// Send a service request message
    Srv(String, M),
}

impl<M> FetchAction<M>
where
    M: std::marker::Send,
{
    /// Method to know if there is still action to execute
    pub fn have_action(&self) -> bool {
        !matches!(self, FetchAction::<M>::None)
    }
}

#[proc(settings = FetcherSettings)]
pub struct FetcherProc {}

#[proc]
impl FetcherProc {
    fn spawn_http_fetch(
        settings: &FetcherSettings,
        target: TargetSetting,
        mut req_rx: mpsc::Receiver<Request<BoxBody<Bytes, Infallible>>>,
        resp_tx: mpsc::Sender<Result<Response<Incoming>, FetcherError<M>>>,
    ) {
        let timeout = settings.timeout;
        let have_time_range = settings.active_time_range.is_some();
        let http1_ctx = settings.get_http1_ctx();
        tokio::spawn(async move {
            let mut msg_to_send;
            'conn: loop {
                // Wait for a message before openning the socket
                msg_to_send = req_rx.recv().await;
                if msg_to_send.is_none() {
                    if let Err(e) = resp_tx.try_send(Err(FetcherError::Other(
                        "Internal HTTP queue is closed".to_string(),
                    ))) {
                        warn!(
                            addr = target.to_string(),
                            "Error during message openning: {e}"
                        );
                    }
                    return;
                }

                match target.connect().await {
                    Ok(stream) => {
                        let is_http2 = stream.selected_alpn_check(|alpn| alpn == b"h2");
                        let stream = TokioIo::new(stream);

                        if is_http2 {
                            match time::timeout(
                                timeout,
                                http2::handshake(TokioExecutor::new(), stream),
                            )
                            .await
                            {
                                Ok(Ok((mut sender, mut connection))) => loop {
                                    tokio::select! {
                                        // Closed the socket
                                        Err(_) = &mut connection => {
                                            debug!(addr = target.to_string(), "Remote close the socket");
                                            continue 'conn;
                                        }
                                        // Send an HTTP request
                                        resp = sender.send_request(msg_to_send.take().unwrap()), if msg_to_send.is_some() => {
                                            match resp {
                                                Ok(r) => {
                                                    if let Err(e) = resp_tx.try_send(Ok(r)) {
                                                        warn!(addr = target.to_string(), "Error during HTTP2 response return: {e}");
                                                    }
                                                }
                                                Err(e) => {
                                                    if let Err(e) = resp_tx.try_send(Err(FetcherError::Hyper(e, target.to_string()))) {
                                                        warn!(addr = target.to_string(), "Error during HTTP2 error response return: {e}");
                                                    }
                                                    continue 'conn;
                                                }
                                            }
                                        }
                                        // Receive a message to send from the queue
                                        Some(mut msg) = req_rx.recv() => {
                                            *msg.version_mut() = http::Version::HTTP_2;
                                            msg_to_send = Some(msg);
                                        }
                                    }
                                },
                                Ok(Err(handshake_error)) => warn!(
                                    addr = target.to_string(),
                                    "HTTP2 handshake error: {handshake_error}"
                                ),
                                Err(_) => warn!(
                                    addr = target.to_string(),
                                    "HTTP2 handshake timeout after {}ms", target.connect_timeout
                                ),
                            }
                        } else {
                            match time::timeout(timeout, http1_ctx.handshake(stream)).await {
                                Ok(Ok((mut sender, mut connection))) => loop {
                                    if let Some(msg) = msg_to_send.take() {
                                        tokio::select! {
                                            // Closed the socket
                                            Err(_) = &mut connection => {
                                                debug!(addr = target.to_string(), "Remote close the socket");
                                                continue 'conn;
                                            }
                                            // Send an HTTP request
                                            resp = sender.send_request(msg) => {
                                                match resp {
                                                    Ok(r) => {
                                                        if let Err(e) = resp_tx.try_send(Ok(r)) {
                                                            warn!(addr = target.to_string(), "Error during HTTP response return: {e}");
                                                        }
                                                    }
                                                    Err(e) => {
                                                        if let Err(e) = resp_tx.try_send(Err(FetcherError::Hyper(e, target.to_string()))) {
                                                            warn!(addr = target.to_string(), "Error during HTTP error response return: {e}");
                                                        }
                                                        continue 'conn;
                                                    }
                                                }
                                            }
                                            // Receive a message to send from the queue
                                            Some(mut msg) = req_rx.recv() => {
                                                *msg.version_mut() = http::Version::HTTP_11;
                                                msg_to_send = Some(msg);
                                            }
                                        }
                                    } else {
                                        tokio::select! {
                                            // Closed the socket
                                            Err(_) = &mut connection => {
                                                continue 'conn;
                                            }
                                            // Receive a message to send from the queue
                                            Some(mut msg) = req_rx.recv() => {
                                                *msg.version_mut() = http::Version::HTTP_11;
                                                msg_to_send = Some(msg);
                                            }
                                        }
                                    }
                                },
                                Ok(Err(handshake_error)) => warn!(
                                    addr = target.to_string(),
                                    "HTTP handshake error: {handshake_error}"
                                ),
                                Err(_) => warn!(
                                    addr = target.to_string(),
                                    "HTTP handshake timeout after {}ms", target.connect_timeout
                                ),
                            }
                        }
                    }
                    Err(e) => {
                        // If the distant have a time range, maybe the distant is not up, so just throw an info log
                        if have_time_range {
                            info!(
                                addr = target.to_string(),
                                "Can't connect to remote: {:?}", e
                            );
                        } else {
                            warn!(
                                addr = target.to_string(),
                                "Can't connect to remote: {:?}", e
                            );
                        }
                    }
                }
            }
        });
    }
}

macro_rules! process_action {
    ($self:ident, $action:ident, $adaptor:ident, $http_req_tx:ident) => {
        match $action {
            FetchAction::Http => {
                let request_builder = if let Some(target) = &$self.settings.target {
                    let mut authority_url = target.url.clone();
                    let _ = authority_url.set_username("");
                    let _ = authority_url.set_password(None);
                    let mut request_builder = Request::builder().header(hyper::header::HOST, authority_url.authority());
                    match $self.settings.auth_method {
                        AuthMethod::Basic => {
                            if let (user, Some(password)) = (target.url.username(), target.url.password()) {
                                if !user.is_empty() {
                                    request_builder = request_builder.header(hyper::header::AUTHORIZATION, format!("Basic {}", STANDARD.encode(format!("{}:{}", user, password))));
                                }
                            }
                        },
                        _ => {},
                    }

                    // TOOD add USER agent
                    request_builder
                } else {
                    Request::builder()
                };
                let request = $adaptor.create_http_request(request_builder)?;
                debug!(addr = $self.settings.target.as_ref().map(|t| t.to_string()), "Send: {:?}", request);
                $http_req_tx.send(request).await.map_err(FetcherError::<M>::from)?;
            }
            FetchAction::Srv(service_name, msg) => {
                debug!("Call Service({}) Fetch action", service_name);
                if let Some(service) = $self.service.get_proc_service(&service_name) {
                    let req_msg = RequestMsg::new(service_name.clone(), msg, $self.proc.get_service_queue());
                    debug!(name: "fetcher_proc", target: "prosa_proc_fetcher::proc", parent: req_msg.get_span(), proc_name = $self.proc.name(), service = service_name, request = format!("{:?}", req_msg.get_data()));
                    service.proc_queue.send(InternalMsg::Request(req_msg)).await?;
                }
            },
            FetchAction::None => { /* No further action to do */ }
        }
    };
}

// Fetcher processor to fetch information from remote systems
#[proc]
impl<A> Proc<A> for FetcherProc
where
    A: Adaptor + FetcherAdaptor<M> + std::marker::Send,
{
    async fn internal_run(
        &mut self,
        _name: String,
    ) -> Result<(), Box<dyn ProcError + Send + Sync>> {
        // Initiate an adaptor for the fetcher processor
        let mut adaptor = A::new(self)?;

        // TODO wait for external service to become available if needed.

        // Declare the processor
        self.proc.add_proc().await?;

        // Interval between each fetch
        let mut fetch_interval = time::interval(self.settings.period);

        // Spawn HTTP task if needed
        let (http_req_tx, http_req_rx) = mpsc::channel(1);
        let (http_resp_tx, mut http_resp_rx) = mpsc::channel(1);
        if let Some(target) = &self.settings.target {
            Self::spawn_http_fetch(&self.settings, target.clone(), http_req_rx, http_resp_tx);
        }

        let mut is_active = true;
        loop {
            tokio::select! {
                _interval = fetch_interval.tick() => if self.settings.is_active() {
                    is_active = true;
                    let action = adaptor.fetch()?;
                    process_action!(self, action, adaptor, http_req_tx);
                } else if is_active {
                    is_active = false;
                    adaptor.end_active_period();
                },
                Some(http_resp) = http_resp_rx.recv() => {
                    let action = adaptor.process_http_response(http_resp).await?;
                    process_action!(self, action, adaptor, http_req_tx);
                }
                Some(msg) = self.internal_rx_queue.recv() => {
                    match msg {
                        InternalMsg::Request(msg) => panic!(
                            "The fetcher processor {} should not receive a request {:?}",
                            self.get_proc_id(),
                            msg
                        ),
                        InternalMsg::Response(msg) => {
                            let action = adaptor.process_service_response(msg)?;
                            process_action!(self, action, adaptor, http_req_tx);
                        },
                        InternalMsg::Error(err) => {
                            let action = adaptor.process_service_error(err)?;
                            process_action!(self, action, adaptor, http_req_tx);
                        },
                        InternalMsg::Command(_) => todo!(),
                        InternalMsg::Config => todo!(),
                        InternalMsg::Service(table) => self.service = table,
                        InternalMsg::Shutdown => {
                            // Stop directly the processor
                            adaptor.terminate();
                            self.proc.remove_proc(None).await?;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}
