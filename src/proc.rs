use std::{convert::Infallible, io, time::Duration};

use base64::{DecodeError, Engine as _, engine::general_purpose::URL_SAFE};
use chrono::{Local, NaiveTime};
use http::Response;
use http_body_util::combinators::BoxBody;
use hyper::{
    Request,
    body::{Bytes, Incoming},
    client::conn::http1,
};
use prosa::{
    core::{
        adaptor::Adaptor,
        error::ProcError,
        msg::{InternalMsg, Msg, RequestMsg},
        proc::{Proc, ProcBusParam as _, proc, proc_settings},
        settings::ProsaConfig,
    },
    io::stream::{Stream, TargetSetting},
    otel::KeyValue,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    sync::{mpsc, watch},
    time,
};
use tracing::{debug, warn};

use crate::{adaptor::FetcherAdaptor, tcp};

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
    /// Authentication with authorization header with provided user password
    #[serde(default = "FetcherSettings::get_default_authorization")]
    pub authorization: bool,
    /// Period where the remote system need to be fetch
    #[serde(default = "FetcherSettings::get_default_period")]
    period: Duration,
    /// Timeout duration for every fetch
    #[serde(default = "FetcherSettings::get_default_timeout")]
    pub(crate) timeout: Duration,
    /// Maximum number of retry to fetch a resource
    #[serde(default = "FetcherSettings::get_default_max_retry")]
    pub(crate) max_retry: u8,
    /// Hour time range when the fetcher execute
    pub(crate) active_time_range: Option<TimeRange>,
    #[serde(default)]
    title_case_headers: bool,
}

impl FetcherSettings {
    fn get_default_authorization() -> bool {
        true
    }

    fn get_default_period() -> Duration {
        Duration::from_secs(60)
    }

    fn get_default_timeout() -> Duration {
        Duration::from_secs(10)
    }

    fn get_default_max_retry() -> u8 {
        2
    }

    /// Create a new Fetcher settings
    pub fn new(
        target: TargetSetting,
        service_name: String,
        authorization: bool,
        period: Duration,
        timeout: Duration,
    ) -> FetcherSettings {
        FetcherSettings {
            target: Some(target),
            service_name: Some(service_name),
            authorization,
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
            authorization: Self::get_default_authorization(),
            period: Self::get_default_period(),
            timeout: Self::get_default_timeout(),
            max_retry: Self::get_default_max_retry(),
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
    /// Send a TCP request message
    Tcp,
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

pub(crate) struct AbortOnDropJoinHandle<T>(pub(crate) tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDropJoinHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) struct PendingHttpRequest {
    pub(crate) request: Request<BoxBody<Bytes, Infallible>>,
    pub(crate) started_at: time::Instant,
    pub(crate) deadline: time::Instant,
}

pub(crate) struct HttpFetchResult<M>
where
    M: std::marker::Send,
{
    pub(crate) response: Result<Response<Incoming>, FetcherError<M>>,
    pub(crate) started_at: time::Instant,
    pub(crate) deadline: time::Instant,
}

struct TcpWorker<M: Send> {
    req_tx: mpsc::Sender<tcp::PendingRequest>,
    resp_rx: mpsc::Receiver<tcp::FetchResult<M>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl<M: Send + 'static> TcpWorker<M> {
    fn new(settings: &FetcherSettings) -> Self {
        let (req_tx, req_rx) = mpsc::channel(1);
        let (resp_tx, resp_rx) = mpsc::channel(1);
        let task = settings.target.as_ref().map(|target| {
            tcp::spawn(
                target.clone(),
                settings.timeout,
                settings.max_retry,
                req_rx,
                resp_tx,
            )
        });
        Self {
            req_tx,
            resp_rx,
            task,
        }
    }
}

#[proc]
impl FetcherProc {
    fn fetch_interval(period: Duration) -> time::Interval {
        let mut interval = time::interval(period);
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        interval
    }

    fn reserve_network_request(pending: &mut bool, deferred: &mut bool) -> bool {
        if *pending {
            *deferred = true;
            false
        } else {
            *pending = true;
            true
        }
    }

    fn reconcile_network_action_after_reload(
        action: FetchAction<M>,
        target_changed: bool,
        deferred_http_action: &mut bool,
        deferred_tcp_action: &mut bool,
        deferred_tick: &mut bool,
    ) -> FetchAction<M> {
        if target_changed {
            *deferred_http_action = false;
            *deferred_tcp_action = false;
            *deferred_tick = false;
            if matches!(action, FetchAction::Http | FetchAction::Tcp) {
                debug!("Discard network follow-up after target configuration changed");
                return FetchAction::None;
            }
        }

        action
    }

    fn http_timeout_error(timeout: Duration, target: &TargetSetting) -> FetcherError<M> {
        FetcherError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("HTTP timeout after {timeout:?} while fetching from `{target}`"),
        ))
    }

    async fn notify_http_timeout<A>(
        settings: &FetcherSettings,
        adaptor: &mut A,
    ) -> Result<FetchAction<M>, FetcherError<M>>
    where
        A: FetcherAdaptor<M> + Send,
    {
        let Some(target) = settings.target.as_ref() else {
            return Err(FetcherError::Other(
                "HTTP response received without a configured target".to_string(),
            ));
        };

        let timeout_error = Self::http_timeout_error(settings.timeout, target);
        match time::timeout(
            settings.timeout,
            adaptor.process_http_response(Err(timeout_error)),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(Self::http_timeout_error(settings.timeout, target)),
        }
    }

    async fn process_http_response<A>(
        settings: &FetcherSettings,
        adaptor: &mut A,
        response: Result<Response<Incoming>, FetcherError<M>>,
        deadline: time::Instant,
    ) -> Result<FetchAction<M>, FetcherError<M>>
    where
        A: FetcherAdaptor<M> + Send,
    {
        if deadline <= time::Instant::now() {
            return Self::notify_http_timeout(settings, adaptor).await;
        }

        match time::timeout_at(deadline, adaptor.process_http_response(response)).await {
            Ok(result) => result,
            Err(_) => Self::notify_http_timeout(settings, adaptor).await,
        }
    }

    fn reload_settings<A>(&self, config: &ProsaConfig, adaptor: &A) -> Option<FetcherSettings>
    where
        A: Adaptor,
    {
        let settings = match config.get_proc::<FetcherSettings>(self.proc.as_ref()) {
            Ok(settings) => settings,
            Err(error) => {
                warn!(
                    "Can't reload settings for processor {}: {error}",
                    self.name()
                );
                return None;
            }
        };

        if settings.period.is_zero() {
            warn!(
                "Can't reload settings for processor {}: fetcher period must be greater than zero",
                self.name()
            );
            return None;
        }

        if let Err(error) = adaptor.reload_config(config.get_adaptor_config(self.proc.as_ref())) {
            warn!(
                "Can't reload adaptor configuration for processor {}: {error}",
                self.name()
            );
            return None;
        }

        Some(settings)
    }

    fn apply_settings(
        &mut self,
        settings: FetcherSettings,
        fetch_interval: &mut time::Interval,
        http_req_tx: &mut mpsc::Sender<PendingHttpRequest>,
        http_resp_rx: &mut mpsc::Receiver<HttpFetchResult<M>>,
        http_task: &mut Option<tokio::task::JoinHandle<()>>,
        tcp_worker: &mut TcpWorker<M>,
    ) {
        let period_changed = self.settings.period != settings.period;
        let http_settings_changed = self.settings.target != settings.target
            || self.settings.timeout != settings.timeout
            || self.settings.max_retry != settings.max_retry
            || self.settings.title_case_headers != settings.title_case_headers;

        if period_changed {
            *fetch_interval = Self::fetch_interval(settings.period);
        }

        if http_settings_changed {
            if let Some(task) = http_task.take() {
                task.abort();
            }

            let (new_http_req_tx, http_req_rx) = mpsc::channel(1);
            let (http_resp_tx, new_http_resp_rx) = mpsc::channel(1);
            *http_req_tx = new_http_req_tx;
            *http_resp_rx = new_http_resp_rx;
            *http_task = settings.target.as_ref().map(|target| {
                Self::spawn_http_fetch(&settings, target.clone(), http_req_rx, http_resp_tx)
            });

            if let Some(task) = tcp_worker.task.take() {
                task.abort();
            }
            *tcp_worker = TcpWorker::new(&settings);
        }

        self.settings = settings;
    }

    async fn process_tcp_response<A>(
        settings: &FetcherSettings,
        adaptor: &mut A,
        response: Result<Stream, FetcherError<M>>,
        deadline: time::Instant,
    ) -> Result<FetchAction<M>, FetcherError<M>>
    where
        A: FetcherAdaptor<M> + Send,
    {
        let target = settings.target.as_ref().ok_or_else(|| {
            FetcherError::Other("TCP response received without a configured target".into())
        })?;
        if deadline > time::Instant::now()
            && let Ok(result) =
                time::timeout_at(deadline, adaptor.process_tcp_response(target, response)).await
        {
            return result;
        }

        match time::timeout(
            settings.timeout,
            adaptor.process_tcp_response(target, Err(tcp::timeout_error(settings.timeout, target))),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(tcp::timeout_error(settings.timeout, target)),
        }
    }

    fn spawn_http_fetch(
        settings: &FetcherSettings,
        target: TargetSetting,
        req_rx: mpsc::Receiver<PendingHttpRequest>,
        resp_tx: mpsc::Sender<HttpFetchResult<M>>,
    ) -> tokio::task::JoinHandle<()> {
        crate::http_fetch::HttpWorker::spawn_http_fetch(settings, target, req_rx, resp_tx)
    }
}

macro_rules! process_action {
    ($self:ident, $action:ident, $adaptor:ident, $http_req_tx:ident, $tcp_req_tx:ident, $network_request_pending:ident, $deferred_http_action:ident, $deferred_tcp_action:ident, $pending_service_action:ident) => {
        match $action {
            FetchAction::Http => {
                if Self::reserve_network_request(
                    &mut $network_request_pending,
                    &mut $deferred_http_action,
                ) {
                    let request_builder = if let Some(target) = &$self.settings.target {
                        let mut authority_url = target.url.clone();
                        let _ = authority_url.set_username("");
                        let _ = authority_url.set_password(None);
                        let mut request_builder = Request::builder().header(hyper::header::HOST, authority_url.authority());
                        if $self.settings.authorization
                            && let Some(authorization) = target.get_authentication()
                        {
                            request_builder = request_builder.header(hyper::header::AUTHORIZATION, authorization);
                        }

                        // TOOD add USER agent
                        request_builder
                    } else {
                        Request::builder()
                    };
                    let request = $adaptor.create_http_request(request_builder)?;
                    debug!(
                        addr = $self.settings.target.as_ref().map(|t| t.to_string()),
                        method = %request.method(),
                        version = ?request.version(),
                        "Send HTTP request"
                    );
                    let started_at = time::Instant::now();
                    let deadline = started_at.checked_add($self.settings.timeout).ok_or_else(|| {
                        FetcherError::<M>::Other("HTTP timeout is too large".to_string())
                    })?;
                    let pending_request = PendingHttpRequest {
                        request,
                        started_at,
                        deadline,
                    };
                    $http_req_tx.try_send(pending_request).map_err(|error| match error {
                        mpsc::error::TrySendError::Closed(pending_request) => {
                            FetcherError::<M>::from(mpsc::error::SendError(pending_request.request))
                        },
                        mpsc::error::TrySendError::Full(_) => FetcherError::<M>::Other(
                            "HTTP request queue is unexpectedly full without a pending request"
                                .to_string(),
                        ),
                    })?;
                } else {
                    debug!("Defer HTTP request while another request is pending");
                }
            }
            FetchAction::Tcp => {
                if Self::reserve_network_request(&mut $network_request_pending, &mut $deferred_tcp_action) {
                    let target = $self.settings.target.as_ref().ok_or_else(|| {
                        FetcherError::<M>::Other("TCP fetch requires a target".into())
                    })?;
                    let request = $adaptor.create_tcp_request(target)?;
                    let started_at = time::Instant::now();
                    let deadline = started_at.checked_add($self.settings.timeout).ok_or_else(|| {
                        FetcherError::<M>::Other("TCP timeout is too large".into())
                    })?;
                    $tcp_req_tx.req_tx.try_send(tcp::PendingRequest { request, started_at, deadline })
                        .map_err(|error| FetcherError::<M>::Other(format!("TCP request queue error: {error}")))?;
                }
            }
            FetchAction::Srv(service_name, msg) => {
                debug!("Call Service({}) Fetch action", service_name);
                if let Some(service) = $self.service.get_proc_service(&service_name) {
                    let req_msg = RequestMsg::new(service_name.clone(), msg, $self.proc.get_service_queue());
                    debug!(name: "fetcher_proc", target: "prosa_proc_fetcher::proc", parent: req_msg.get_span(), proc_name = $self.proc.name(), service = service_name);
                    service.proc_queue.send(InternalMsg::Request(req_msg)).await?;
                } else {
                    warn!(service = service_name, "Service unavailable; deferring fetch action");
                    $pending_service_action = Some((service_name, msg));
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
    async fn internal_run(&mut self) -> Result<(), Box<dyn ProcError + Send + Sync>> {
        if self.settings.period.is_zero() {
            return Err(Box::new(FetcherError::<M>::Other(
                "Fetcher period must be greater than zero".to_string(),
            )));
        }

        // Initiate an adaptor for the fetcher processor
        let mut adaptor = A::new(self)?;

        // Declare the processor
        self.proc.add_proc().await?;

        // Interval between each fetch
        let mut fetch_interval = Self::fetch_interval(self.settings.period);

        // Spawn network workers if needed
        let (mut http_req_tx, http_req_rx) = mpsc::channel(1);
        let (http_resp_tx, mut http_resp_rx) = mpsc::channel(1);
        let mut http_task = self.settings.target.as_ref().map(|target| {
            Self::spawn_http_fetch(&self.settings, target.clone(), http_req_rx, http_resp_tx)
        });
        let mut tcp_worker = TcpWorker::new(&self.settings);

        let meter = self.proc.meter("fetcher");
        let action_histogram = meter
            .u64_histogram("prosa_fetcher_duration")
            .with_description("Fetcher duration histogram")
            .build();

        let mut is_active = true;
        let mut network_request_pending = false;
        let mut deferred_http_action = false;
        let mut deferred_tcp_action = false;
        let mut deferred_tick = false;
        let mut pending_config: Option<std::sync::Arc<ProsaConfig>> = None;
        let mut pending_service_action = None;
        loop {
            tokio::select! {
                _interval = fetch_interval.tick() => if self.settings.is_active() {
                    is_active = true;
                    if network_request_pending {
                        deferred_tick = true;
                    } else {
                        let action = if let Some((service_name, msg)) = pending_service_action.take() {
                            FetchAction::Srv(service_name, msg)
                        } else {
                            adaptor.fetch()?
                        };
                        process_action!(self, action, adaptor, http_req_tx, tcp_worker, network_request_pending, deferred_http_action, deferred_tcp_action, pending_service_action);
                    }
                } else if is_active {
                    is_active = false;
                    adaptor.end_active_period();
                },
                Some(http_result) = http_resp_rx.recv() => {
                    if !network_request_pending {
                        return Err(FetcherError::<M>::Other(
                            "HTTP response received without a pending request".to_string(),
                        ).into());
                    }
                    let HttpFetchResult {
                        response,
                        started_at,
                        deadline,
                    } = http_result;
                    let mut histogram_attributes = vec![
                        KeyValue::new("type", "http"),
                        KeyValue::new("code", response.as_ref().map(|r| r.status().as_u16()).unwrap_or(502) as i64),
                    ];
                    if let Some(target) = &self.settings.target {
                        histogram_attributes.push(KeyValue::new("target", target.to_string()));
                    }

                    let action = Self::process_http_response(
                        &self.settings,
                        &mut adaptor,
                        response,
                        deadline,
                    ).await;
                    action_histogram.record(
                        started_at.elapsed().as_millis() as u64,
                        &histogram_attributes,
                    );
                    let action = action?;
                    network_request_pending = false;
                    let mut target_changed = false;
                    if let Some(config) = pending_config.take()
                        && let Some(settings) = self.reload_settings(config.as_ref(), &adaptor)
                    {
                        target_changed = self.settings.target != settings.target;
                        self.apply_settings(
                            settings,
                            &mut fetch_interval,
                            &mut http_req_tx,
                            &mut http_resp_rx,
                            &mut http_task,
                            &mut tcp_worker,
                        );
                    }
                    let action = Self::reconcile_network_action_after_reload(
                        action,
                        target_changed,
                        &mut deferred_http_action,
                        &mut deferred_tcp_action,
                        &mut deferred_tick,
                    );
                    process_action!(self, action, adaptor, http_req_tx, tcp_worker, network_request_pending, deferred_http_action, deferred_tcp_action, pending_service_action);
                    if !network_request_pending && std::mem::take(&mut deferred_http_action) {
                        let action = FetchAction::Http;
                        process_action!(self, action, adaptor, http_req_tx, tcp_worker, network_request_pending, deferred_http_action, deferred_tcp_action, pending_service_action);
                    }
                    if !network_request_pending && std::mem::take(&mut deferred_tcp_action) {
                        let action = FetchAction::Tcp;
                        process_action!(self, action, adaptor, http_req_tx, tcp_worker, network_request_pending, deferred_http_action, deferred_tcp_action, pending_service_action);
                    }
                    if !network_request_pending && std::mem::take(&mut deferred_tick) && self.settings.is_active() {
                        let action = adaptor.fetch()?;
                        process_action!(self, action, adaptor, http_req_tx, tcp_worker, network_request_pending, deferred_http_action, deferred_tcp_action, pending_service_action);
                    }
                }
                Some(tcp_result) = tcp_worker.resp_rx.recv() => {
                    if !network_request_pending {
                        return Err(FetcherError::<M>::Other("TCP response received without a pending request".into()).into());
                    }
                    let tcp::FetchResult { response, started_at, deadline, .. } = tcp_result;
                    let code = if response.is_ok() { 0 } else { 1 };
                    let action = Self::process_tcp_response(&self.settings, &mut adaptor, response, deadline).await;
                    let mut attributes = vec![KeyValue::new("type", "tcp"), KeyValue::new("code", code)];
                    if let Some(target) = &self.settings.target {
                        attributes.push(KeyValue::new("target", target.to_string()));
                    }
                    action_histogram.record(started_at.elapsed().as_millis() as u64, &attributes);
                    let action = action?;
                    network_request_pending = false;
                    let mut target_changed = false;
                    if let Some(config) = pending_config.take()
                        && let Some(settings) = self.reload_settings(config.as_ref(), &adaptor)
                    {
                        target_changed = self.settings.target != settings.target;
                        self.apply_settings(settings, &mut fetch_interval, &mut http_req_tx, &mut http_resp_rx, &mut http_task, &mut tcp_worker);
                    }
                    let action = Self::reconcile_network_action_after_reload(
                        action,
                        target_changed,
                        &mut deferred_http_action,
                        &mut deferred_tcp_action,
                        &mut deferred_tick,
                    );
                    process_action!(self, action, adaptor, http_req_tx, tcp_worker, network_request_pending, deferred_http_action, deferred_tcp_action, pending_service_action);
                    if !network_request_pending && std::mem::take(&mut deferred_http_action) {
                        let action = FetchAction::Http;
                        process_action!(self, action, adaptor, http_req_tx, tcp_worker, network_request_pending, deferred_http_action, deferred_tcp_action, pending_service_action);
                    }
                    if !network_request_pending && std::mem::take(&mut deferred_tcp_action) {
                        let action = FetchAction::Tcp;
                        process_action!(self, action, adaptor, http_req_tx, tcp_worker, network_request_pending, deferred_http_action, deferred_tcp_action, pending_service_action);
                    }
                    if !network_request_pending && std::mem::take(&mut deferred_tick) && self.settings.is_active() {
                        let action = adaptor.fetch()?;
                        process_action!(self, action, adaptor, http_req_tx, tcp_worker, network_request_pending, deferred_http_action, deferred_tcp_action, pending_service_action);
                    }
                }
                Some(msg) = self.internal_rx_queue.recv() => {
                    match msg {
                        InternalMsg::Request(msg) => panic!(
                            "The fetcher processor {} should not receive a request {:?}",
                            self.get_proc_id(),
                            msg
                        ),
                        InternalMsg::Response(msg) => {
                            action_histogram.record(
                                msg.elapsed().as_millis() as u64,
                                &[
                                    KeyValue::new("type", "service"),
                                    KeyValue::new("service", msg.get_service().clone()),
                                    KeyValue::new("code", 0),
                                ],
                            );
                            let action = adaptor.process_service_response(msg)?;
                            process_action!(self, action, adaptor, http_req_tx, tcp_worker, network_request_pending, deferred_http_action, deferred_tcp_action, pending_service_action);
                        },
                        InternalMsg::Error(err) => {
                            action_histogram.record(
                                err.elapsed().as_millis() as u64,
                                &[
                                    KeyValue::new("type", "service"),
                                    KeyValue::new("service", err.get_service().clone()),
                                    KeyValue::new("code", err.get_err().get_code() as i64),
                                ],
                            );
                            let action = adaptor.process_service_error(err)?;
                            process_action!(self, action, adaptor, http_req_tx, tcp_worker, network_request_pending, deferred_http_action, deferred_tcp_action, pending_service_action);
                        },
                        InternalMsg::Config(config) => {
                            if network_request_pending {
                                pending_config = Some(config);
                                continue;
                            }

                            if let Some(settings) = self.reload_settings(config.as_ref(), &adaptor) {
                                self.apply_settings(
                                    settings,
                                    &mut fetch_interval,
                                    &mut http_req_tx,
                                    &mut http_resp_rx,
                                    &mut http_task,
                                    &mut tcp_worker,
                                );
                            }
                        },
                        InternalMsg::Service(table) => {
                            self.service = table;
                            if self.settings.is_active()
                                && let Some((service_name, msg)) = pending_service_action.take()
                            {
                                let action = FetchAction::Srv(service_name, msg);
                                process_action!(self, action, adaptor, http_req_tx, tcp_worker, network_request_pending, deferred_http_action, deferred_tcp_action, pending_service_action);
                            }
                        },
                        InternalMsg::Shutdown => {
                            // Stop directly the processor
                            if let Some(task) = http_task.take() {
                                task.abort();
                            }
                            if let Some(task) = tcp_worker.task.take() {
                                task.abort();
                            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt as _, Empty};
    use prosa_utils::msg::simple_string_tvf::SimpleStringTvf;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };
    use url::Url;

    #[derive(Default)]
    struct BodyReadingAdaptor {
        timeout_reported: bool,
        stall_once: bool,
    }

    impl Adaptor for BodyReadingAdaptor {
        fn terminate(&self) {}
    }

    impl FetcherAdaptor<SimpleStringTvf> for BodyReadingAdaptor {
        fn new(
            _proc: &FetcherProc<SimpleStringTvf>,
        ) -> Result<Self, FetcherError<SimpleStringTvf>> {
            Ok(Self::default())
        }

        fn fetch(&mut self) -> Result<FetchAction<SimpleStringTvf>, FetcherError<SimpleStringTvf>> {
            Ok(FetchAction::None)
        }

        fn create_http_request(
            &self,
            _request_builder: http::request::Builder,
        ) -> Result<Request<BoxBody<Bytes, Infallible>>, FetcherError<SimpleStringTvf>> {
            Ok(request())
        }

        async fn process_http_response(
            &mut self,
            response: Result<Response<Incoming>, FetcherError<SimpleStringTvf>>,
        ) -> Result<FetchAction<SimpleStringTvf>, FetcherError<SimpleStringTvf>> {
            if std::mem::take(&mut self.stall_once) {
                time::sleep(Duration::from_secs(1)).await;
            }

            match response {
                Ok(response) => {
                    response
                        .into_body()
                        .collect()
                        .await
                        .map_err(|error| FetcherError::Hyper(error, "test".to_string()))?;
                }
                Err(FetcherError::Io(error)) if error.kind() == io::ErrorKind::TimedOut => {
                    self.timeout_reported = true;
                }
                Err(error) => return Err(error),
            }

            Ok(FetchAction::None)
        }

        async fn process_tcp_response(
            &mut self,
            _target: &TargetSetting,
            response: Result<Stream, FetcherError<SimpleStringTvf>>,
        ) -> Result<FetchAction<SimpleStringTvf>, FetcherError<SimpleStringTvf>> {
            if std::mem::take(&mut self.stall_once) {
                time::sleep(Duration::from_secs(1)).await;
            }
            match response {
                Err(FetcherError::Io(error)) if error.kind() == io::ErrorKind::TimedOut => {
                    self.timeout_reported = true;
                }
                Err(error) => return Err(error),
                Ok(_) => {}
            }
            Ok(FetchAction::None)
        }
    }

    fn request() -> Request<BoxBody<Bytes, Infallible>> {
        Request::builder()
            .uri("/")
            .header(hyper::header::HOST, "localhost")
            .body(Empty::<Bytes>::new().boxed())
            .expect("test request should be valid")
    }

    fn pending_request(timeout: Duration) -> PendingHttpRequest {
        let started_at = time::Instant::now();
        PendingHttpRequest {
            request: request(),
            started_at,
            deadline: started_at + timeout,
        }
    }

    #[tokio::test]
    async fn coalesces_overlapping_network_requests() {
        time::timeout(Duration::from_secs(1), async {
            let mut http_request_pending = false;
            let mut deferred_http_action = false;

            assert!(FetcherProc::<SimpleStringTvf>::reserve_network_request(
                &mut http_request_pending,
                &mut deferred_http_action,
            ));
            assert!(http_request_pending);
            assert!(!deferred_http_action);

            assert!(!FetcherProc::<SimpleStringTvf>::reserve_network_request(
                &mut http_request_pending,
                &mut deferred_http_action,
            ));
            assert!(http_request_pending);
            assert!(deferred_http_action);

            http_request_pending = false;
            assert!(std::mem::take(&mut deferred_http_action));
            assert!(FetcherProc::<SimpleStringTvf>::reserve_network_request(
                &mut http_request_pending,
                &mut deferred_http_action,
            ));

            let interval = FetcherProc::<SimpleStringTvf>::fetch_interval(Duration::from_secs(1));
            assert!(matches!(
                interval.missed_tick_behavior(),
                time::MissedTickBehavior::Skip
            ));
        })
        .await
        .expect("HTTP request scheduling should not block");
    }

    #[tokio::test]
    async fn discards_network_actions_after_target_reload() {
        time::timeout(Duration::from_secs(1), async {
            let mut deferred_http_action = true;
            let mut deferred_tcp_action = true;
            let mut deferred_tick = true;
            let action = FetcherProc::<SimpleStringTvf>::reconcile_network_action_after_reload(
                FetchAction::Http,
                true,
                &mut deferred_http_action,
                &mut deferred_tcp_action,
                &mut deferred_tick,
            );

            assert!(matches!(action, FetchAction::None));
            assert!(!deferred_http_action);
            assert!(!deferred_tcp_action);
            assert!(!deferred_tick);

            let action = FetcherProc::<SimpleStringTvf>::reconcile_network_action_after_reload(
                FetchAction::Tcp,
                true,
                &mut deferred_http_action,
                &mut deferred_tcp_action,
                &mut deferred_tick,
            );
            assert!(matches!(action, FetchAction::None));
        })
        .await
        .expect("reload action reconciliation should not block");
    }

    #[tokio::test]
    async fn uses_request_deadline_during_response_processing() {
        time::timeout(Duration::from_millis(250), async {
            let target = TargetSetting::from(
                Url::parse("http://127.0.0.1").expect("test URL should be valid"),
            );
            let settings = FetcherSettings::new(
                target,
                String::new(),
                false,
                Duration::from_secs(2),
                Duration::from_secs(1),
            );
            let mut adaptor = BodyReadingAdaptor {
                stall_once: true,
                ..Default::default()
            };

            let action = FetcherProc::<SimpleStringTvf>::process_http_response(
                &settings,
                &mut adaptor,
                Err(FetcherError::Other("test response".to_string())),
                time::Instant::now() + Duration::from_millis(20),
            )
            .await
            .expect("the adaptor should handle the request deadline");

            assert!(matches!(action, FetchAction::None));
            assert!(adaptor.timeout_reported);
        })
        .await
        .expect("response processing should use the remaining request deadline");
    }

    #[tokio::test]
    async fn uses_tcp_deadline_during_response_processing() {
        time::timeout(Duration::from_millis(250), async {
            let target = TargetSetting::from(Url::parse("tcp://127.0.0.1:3493/ups").unwrap());
            let settings = FetcherSettings::new(
                target,
                String::new(),
                false,
                Duration::from_secs(2),
                Duration::from_secs(1),
            );
            let mut adaptor = BodyReadingAdaptor {
                stall_once: true,
                ..Default::default()
            };
            let action = FetcherProc::<SimpleStringTvf>::process_tcp_response(
                &settings,
                &mut adaptor,
                Err(FetcherError::Other("test response".into())),
                time::Instant::now() + Duration::from_millis(20),
            )
            .await
            .unwrap();
            assert!(matches!(action, FetchAction::None));
            assert!(adaptor.timeout_reported);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn reports_expired_deadline_before_processing_response() {
        time::timeout(Duration::from_secs(1), async {
            let target = TargetSetting::from(
                Url::parse("http://127.0.0.1").expect("test URL should be valid"),
            );
            let settings = FetcherSettings::new(
                target,
                String::new(),
                false,
                Duration::from_secs(2),
                Duration::from_secs(1),
            );
            let mut adaptor = BodyReadingAdaptor::default();

            let action = FetcherProc::<SimpleStringTvf>::process_http_response(
                &settings,
                &mut adaptor,
                Err(FetcherError::Other("stale response".to_string())),
                time::Instant::now(),
            )
            .await
            .expect("the adaptor should receive a timeout for an expired response");

            assert!(matches!(action, FetchAction::None));
            assert!(adaptor.timeout_reported);
        })
        .await
        .expect("an expired response should not be processed normally");
    }

    #[tokio::test]
    async fn expired_request_deadline_skips_connection_retries() {
        time::timeout(Duration::from_secs(1), async {
            let target = TargetSetting::from(
                Url::parse("http://127.0.0.1:9").expect("test URL should be valid"),
            );
            let mut settings = FetcherSettings::new(
                target.clone(),
                String::new(),
                false,
                Duration::from_secs(2),
                Duration::from_secs(1),
            );
            settings.max_retry = 2;

            let (req_tx, req_rx) = mpsc::channel(1);
            let (resp_tx, mut resp_rx) = mpsc::channel(1);
            let worker = FetcherProc::<SimpleStringTvf>::spawn_http_fetch(
                &settings, target, req_rx, resp_tx,
            );
            let started_at = time::Instant::now();
            req_tx
                .send(PendingHttpRequest {
                    request: request(),
                    started_at,
                    deadline: started_at,
                })
                .await
                .expect("HTTP worker should receive the expired request");

            let response = resp_rx
                .recv()
                .await
                .expect("HTTP worker should report the expired request");
            assert!(matches!(
                response.response,
                Err(FetcherError::Io(error)) if error.kind() == io::ErrorKind::TimedOut
            ));
            worker.abort();
        })
        .await
        .expect("an expired request should not consume its retry budget");
    }

    #[tokio::test]
    async fn reports_http_response_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener should have an address");
        let server = tokio::spawn(async move {
            let (_stream, _) = listener
                .accept()
                .await
                .expect("test listener should accept a connection");
            time::sleep(Duration::from_secs(1)).await;
        });

        let target = TargetSetting::from(
            Url::parse(&format!("http://{addr}")).expect("test URL should be valid"),
        );
        let mut settings = FetcherSettings::new(
            target.clone(),
            String::new(),
            false,
            Duration::from_secs(1),
            Duration::from_millis(20),
        );
        settings.max_retry = 0;

        let (req_tx, req_rx) = mpsc::channel(1);
        let (resp_tx, mut resp_rx) = mpsc::channel(1);
        let worker =
            FetcherProc::<SimpleStringTvf>::spawn_http_fetch(&settings, target, req_rx, resp_tx);

        req_tx
            .send(pending_request(settings.timeout))
            .await
            .expect("HTTP worker should receive the request");
        let response = time::timeout(Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("HTTP worker should respond before the test deadline")
            .expect("HTTP response queue should remain open");

        assert!(matches!(
            response.response,
            Err(FetcherError::Io(error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        worker.abort();
        server.abort();
    }

    #[tokio::test]
    async fn returns_response_when_server_closes_connection() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener should have an address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("test listener should accept a connection");
            let mut request_buffer = [0; 1];
            stream
                .read_exact(&mut request_buffer)
                .await
                .expect("test server should read the request");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx")
                .await
                .expect("test server should write the response");
        });

        let target = TargetSetting::from(
            Url::parse(&format!("http://{addr}")).expect("test URL should be valid"),
        );
        let mut settings = FetcherSettings::new(
            target.clone(),
            String::new(),
            false,
            Duration::from_secs(1),
            Duration::from_millis(200),
        );
        settings.max_retry = 0;

        let (req_tx, req_rx) = mpsc::channel(1);
        let (resp_tx, mut resp_rx) = mpsc::channel(1);
        let worker =
            FetcherProc::<SimpleStringTvf>::spawn_http_fetch(&settings, target, req_rx, resp_tx);
        let pending_request = pending_request(settings.timeout);
        let request_started_at = pending_request.started_at;
        req_tx
            .send(pending_request)
            .await
            .expect("HTTP worker should receive the request");

        let result = time::timeout(Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("HTTP worker should return the response before the test deadline")
            .expect("HTTP response queue should remain open");
        assert_eq!(request_started_at, result.started_at);
        let response = result
            .response
            .expect("connection close must not replace a valid response");
        assert_eq!(http::StatusCode::OK, response.status());

        let body = time::timeout(Duration::from_secs(1), response.into_body().collect())
            .await
            .expect("response body should complete before the test deadline")
            .expect("response body should be valid")
            .to_bytes();
        assert_eq!(Bytes::from_static(b"x"), body);

        worker.abort();
        time::timeout(Duration::from_secs(1), server)
            .await
            .expect("test server should stop before the test deadline")
            .expect("test server task should succeed");
    }

    #[tokio::test]
    async fn reports_http_body_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener should have an address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("test listener should accept a connection");
            let mut request_buffer = [0; 1];
            stream
                .read_exact(&mut request_buffer)
                .await
                .expect("test server should read the request");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx")
                .await
                .expect("test server should write response headers");
            time::sleep(Duration::from_secs(1)).await;
        });

        let target = TargetSetting::from(
            Url::parse(&format!("http://{addr}")).expect("test URL should be valid"),
        );
        let mut settings = FetcherSettings::new(
            target.clone(),
            String::new(),
            false,
            Duration::from_secs(1),
            Duration::from_millis(20),
        );
        settings.max_retry = 0;

        let (req_tx, req_rx) = mpsc::channel(1);
        let (resp_tx, mut resp_rx) = mpsc::channel(1);
        let worker = FetcherProc::<SimpleStringTvf>::spawn_http_fetch(
            &settings,
            settings.target.clone().expect("test target"),
            req_rx,
            resp_tx,
        );
        req_tx
            .send(pending_request(settings.timeout))
            .await
            .expect("HTTP worker should receive the request");
        let response = time::timeout(Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("HTTP worker should return the response headers")
            .expect("HTTP response queue should remain open");
        let HttpFetchResult {
            response, deadline, ..
        } = response;

        let mut adaptor = BodyReadingAdaptor::default();
        let action = time::timeout(
            Duration::from_secs(1),
            FetcherProc::<SimpleStringTvf>::process_http_response(
                &settings,
                &mut adaptor,
                response,
                deadline,
            ),
        )
        .await
        .expect("response body processing should be bounded")
        .expect("the adaptor should handle the timeout");

        assert!(matches!(action, FetchAction::None));
        assert!(adaptor.timeout_reported);
        worker.abort();
        server.abort();
    }

    #[tokio::test]
    async fn stops_after_connection_retry_budget_is_exhausted() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener should have an address");
        drop(listener);

        let mut target = TargetSetting::from(
            Url::parse(&format!("http://{addr}")).expect("test URL should be valid"),
        );
        target.connect_timeout = 20;
        let mut settings = FetcherSettings::new(
            target.clone(),
            String::new(),
            false,
            Duration::from_secs(1),
            Duration::from_millis(20),
        );
        settings.max_retry = 2;

        let (req_tx, req_rx) = mpsc::channel(1);
        let (resp_tx, mut resp_rx) = mpsc::channel(2);
        let worker =
            FetcherProc::<SimpleStringTvf>::spawn_http_fetch(&settings, target, req_rx, resp_tx);

        req_tx
            .send(pending_request(settings.timeout))
            .await
            .expect("HTTP worker should receive the request");
        let response = time::timeout(Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("HTTP worker should exhaust retries before the test deadline")
            .expect("HTTP response queue should remain open");
        assert!(matches!(response.response, Err(FetcherError::Io(_))));

        assert!(
            time::timeout(Duration::from_millis(50), resp_rx.recv())
                .await
                .is_err(),
            "HTTP worker must wait for a new request after retry exhaustion"
        );
        worker.abort();
    }
}
