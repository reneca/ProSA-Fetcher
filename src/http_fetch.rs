use std::{io, marker::PhantomData, time::Duration};

use http::Response;
use hyper::{body::Incoming, client::conn::http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use prosa::io::stream::TargetSetting;
use tokio::{sync::mpsc, time};
use tracing::{debug, error, warn};

use crate::proc::{
    AbortOnDropJoinHandle, FetcherError, FetcherSettings, HttpFetchResult, PendingHttpRequest,
};

pub(super) struct HttpWorker<M: Send>(PhantomData<M>);

impl<M: Send + 'static> HttpWorker<M> {
    fn http_timeout_error(timeout: Duration, target: &TargetSetting) -> FetcherError<M> {
        FetcherError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("HTTP timeout after {timeout:?} while fetching from `{target}`"),
        ))
    }

    async fn return_http_result(
        resp_tx: &mpsc::Sender<HttpFetchResult<M>>,
        response: Result<Response<Incoming>, FetcherError<M>>,
        started_at: time::Instant,
        deadline: time::Instant,
        target: &TargetSetting,
        stage: &'static str,
    ) {
        if let Err(send_error) = resp_tx
            .send(HttpFetchResult {
                response,
                started_at,
                deadline,
            })
            .await
        {
            warn!(
                addr = target.to_string(),
                "Error returning {stage} result: {send_error}"
            );
        }
    }

    async fn return_pending_http_error(
        pending_request: &mut Option<PendingHttpRequest>,
        retry_count: &mut u8,
        resp_tx: &mpsc::Sender<HttpFetchResult<M>>,
        fetch_error: FetcherError<M>,
        target: &TargetSetting,
        stage: &'static str,
    ) {
        error!(
            addr = target.to_string(),
            error = %fetch_error,
            "{stage} failed after {retry_count} retries"
        );
        *retry_count = 0;
        let Some(pending_request) = pending_request.take() else {
            warn!(
                addr = target.to_string(),
                "Can't return {stage} failure without a pending HTTP request"
            );
            return;
        };
        Self::return_http_result(
            resp_tx,
            Err(fetch_error),
            pending_request.started_at,
            pending_request.deadline,
            target,
            stage,
        )
        .await;
    }

    async fn retry_http_connection(
        pending_request: &mut Option<PendingHttpRequest>,
        retry_count: &mut u8,
        max_retry: u8,
        resp_tx: &mpsc::Sender<HttpFetchResult<M>>,
        fetch_error: FetcherError<M>,
        target: &TargetSetting,
        stage: &'static str,
    ) {
        if *retry_count < max_retry {
            *retry_count += 1;
            warn!(
                addr = target.to_string(),
                error = %fetch_error,
                "{stage} failed; retry {retry_count}/{max_retry}"
            );
            return;
        }

        Self::return_pending_http_error(
            pending_request,
            retry_count,
            resp_tx,
            fetch_error,
            target,
            stage,
        )
        .await;
    }

    pub(super) fn spawn_http_fetch(
        settings: &FetcherSettings,
        target: TargetSetting,
        mut req_rx: mpsc::Receiver<PendingHttpRequest>,
        resp_tx: mpsc::Sender<HttpFetchResult<M>>,
    ) -> tokio::task::JoinHandle<()> {
        let timeout = settings.timeout;
        let http1_ctx = settings.get_http1_ctx();
        let max_retry = settings.max_retry;
        tokio::spawn(async move {
            let mut msg_to_send = None;
            let mut nb_retry = 0;
            'conn: loop {
                // Wait for a message before openning the socket
                if msg_to_send.is_none() {
                    msg_to_send = req_rx.recv().await;
                    if msg_to_send.is_none() {
                        return;
                    }
                }

                let deadline = msg_to_send
                    .as_ref()
                    .expect("HTTP request must be present before connecting")
                    .deadline;
                if deadline <= time::Instant::now() {
                    Self::return_pending_http_error(
                        &mut msg_to_send,
                        &mut nb_retry,
                        &resp_tx,
                        Self::http_timeout_error(timeout, &target),
                        &target,
                        "HTTP connection",
                    )
                    .await;
                    continue;
                }
                match time::timeout_at(deadline, target.connect()).await {
                    Ok(Ok(stream)) => {
                        let is_http2 = stream.selected_alpn_check(|alpn| alpn == b"h2");
                        let stream = TokioIo::new(stream);

                        if is_http2 {
                            match time::timeout_at(
                                deadline,
                                http2::handshake(TokioExecutor::new(), stream),
                            )
                            .await
                            {
                                Ok(Ok((mut sender, connection))) => {
                                    let mut connection_task =
                                        AbortOnDropJoinHandle(tokio::spawn(connection));
                                    loop {
                                        if let Some(pending_request) = msg_to_send.take() {
                                            let PendingHttpRequest {
                                                mut request,
                                                started_at,
                                                deadline,
                                            } = pending_request;
                                            if deadline <= time::Instant::now() {
                                                nb_retry = 0;
                                                Self::return_http_result(
                                                    &resp_tx,
                                                    Err(Self::http_timeout_error(timeout, &target)),
                                                    started_at,
                                                    deadline,
                                                    &target,
                                                    "HTTP2 timeout",
                                                )
                                                .await;
                                                continue;
                                            }
                                            *request.version_mut() = http::Version::HTTP_2;
                                            match time::timeout_at(
                                                deadline,
                                                sender.try_send_request(request),
                                            )
                                            .await
                                            {
                                                Ok(Ok(r)) => {
                                                    nb_retry = 0;
                                                    Self::return_http_result(
                                                        &resp_tx,
                                                        Ok(r),
                                                        started_at,
                                                        deadline,
                                                        &target,
                                                        "HTTP2 response",
                                                    )
                                                    .await;
                                                }
                                                Ok(Err(mut e)) => {
                                                    let retry_msg = e.take_message();
                                                    let hyper_err = e.into_error();
                                                    if let Some(request) = retry_msg
                                                        && nb_retry < max_retry
                                                        && time::Instant::now() < deadline
                                                    {
                                                        msg_to_send = Some(PendingHttpRequest {
                                                            request,
                                                            started_at,
                                                            deadline,
                                                        });
                                                        nb_retry += 1;
                                                        continue 'conn;
                                                    }

                                                    error!(
                                                        addr = target.to_string(),
                                                        "Failed to fetch HTTP2 because of `{hyper_err}`, after {nb_retry}/{max_retry} retries"
                                                    );
                                                    nb_retry = 0;
                                                    Self::return_http_result(
                                                        &resp_tx,
                                                        Err(FetcherError::Hyper(
                                                            hyper_err,
                                                            target.to_string(),
                                                        )),
                                                        started_at,
                                                        deadline,
                                                        &target,
                                                        "HTTP2 error",
                                                    )
                                                    .await;
                                                    continue 'conn;
                                                }
                                                Err(_) => {
                                                    error!(
                                                        addr = target.to_string(),
                                                        "HTTP2 response timeout after {timeout:?}"
                                                    );
                                                    nb_retry = 0;
                                                    Self::return_http_result(
                                                        &resp_tx,
                                                        Err(Self::http_timeout_error(
                                                            timeout, &target,
                                                        )),
                                                        started_at,
                                                        deadline,
                                                        &target,
                                                        "HTTP2 timeout",
                                                    )
                                                    .await;
                                                    continue 'conn;
                                                }
                                            }
                                        } else {
                                            tokio::select! {
                                                connection_result = &mut connection_task.0 => {
                                                    match connection_result {
                                                        Ok(Ok(())) => debug!(addr = target.to_string(), "Remote closed the HTTP2 connection"),
                                                        Ok(Err(error)) => debug!(addr = target.to_string(), error = %error, "HTTP2 connection closed with an error"),
                                                        Err(error) => warn!(addr = target.to_string(), error = %error, "HTTP2 connection task failed"),
                                                    }
                                                    continue 'conn;
                                                }
                                                // Receive a message to send from the queue
                                                pending_request = req_rx.recv() => {
                                                    let Some(mut pending_request) = pending_request else {
                                                        return;
                                                    };
                                                    *pending_request.request.version_mut() = http::Version::HTTP_2;
                                                    msg_to_send = Some(pending_request);
                                                }
                                            }
                                        }
                                    }
                                }
                                Ok(Err(handshake_error)) => {
                                    Self::retry_http_connection(
                                        &mut msg_to_send,
                                        &mut nb_retry,
                                        max_retry,
                                        &resp_tx,
                                        FetcherError::Hyper(handshake_error, target.to_string()),
                                        &target,
                                        "HTTP2 handshake",
                                    )
                                    .await;
                                }
                                Err(_) => {
                                    Self::return_pending_http_error(
                                        &mut msg_to_send,
                                        &mut nb_retry,
                                        &resp_tx,
                                        Self::http_timeout_error(timeout, &target),
                                        &target,
                                        "HTTP2 handshake",
                                    )
                                    .await;
                                }
                            }
                        } else {
                            match time::timeout_at(deadline, http1_ctx.handshake(stream)).await {
                                Ok(Ok((mut sender, connection))) => {
                                    let mut connection_task =
                                        AbortOnDropJoinHandle(tokio::spawn(connection));
                                    loop {
                                        if let Some(pending_request) = msg_to_send.take() {
                                            let PendingHttpRequest {
                                                mut request,
                                                started_at,
                                                deadline,
                                            } = pending_request;
                                            if deadline <= time::Instant::now() {
                                                nb_retry = 0;
                                                Self::return_http_result(
                                                    &resp_tx,
                                                    Err(Self::http_timeout_error(timeout, &target)),
                                                    started_at,
                                                    deadline,
                                                    &target,
                                                    "HTTP1 timeout",
                                                )
                                                .await;
                                                continue;
                                            }
                                            *request.version_mut() = http::Version::HTTP_11;
                                            match time::timeout_at(
                                                deadline,
                                                sender.try_send_request(request),
                                            )
                                            .await
                                            {
                                                Ok(Ok(r)) => {
                                                    nb_retry = 0;
                                                    Self::return_http_result(
                                                        &resp_tx,
                                                        Ok(r),
                                                        started_at,
                                                        deadline,
                                                        &target,
                                                        "HTTP1 response",
                                                    )
                                                    .await;
                                                }
                                                Ok(Err(mut e)) => {
                                                    let retry_msg = e.take_message();
                                                    let hyper_err = e.into_error();
                                                    if let Some(request) = retry_msg
                                                        && nb_retry < max_retry
                                                        && time::Instant::now() < deadline
                                                    {
                                                        msg_to_send = Some(PendingHttpRequest {
                                                            request,
                                                            started_at,
                                                            deadline,
                                                        });
                                                        nb_retry += 1;
                                                        continue 'conn;
                                                    }

                                                    error!(
                                                        addr = target.to_string(),
                                                        "Failed to fetch HTTP1 because of `{hyper_err}`, after {nb_retry}/{max_retry} retries"
                                                    );
                                                    nb_retry = 0;
                                                    Self::return_http_result(
                                                        &resp_tx,
                                                        Err(FetcherError::Hyper(
                                                            hyper_err,
                                                            target.to_string(),
                                                        )),
                                                        started_at,
                                                        deadline,
                                                        &target,
                                                        "HTTP1 error",
                                                    )
                                                    .await;
                                                    continue 'conn;
                                                }
                                                Err(_) => {
                                                    error!(
                                                        addr = target.to_string(),
                                                        "HTTP1 response timeout after {timeout:?}"
                                                    );
                                                    nb_retry = 0;
                                                    Self::return_http_result(
                                                        &resp_tx,
                                                        Err(Self::http_timeout_error(
                                                            timeout, &target,
                                                        )),
                                                        started_at,
                                                        deadline,
                                                        &target,
                                                        "HTTP1 timeout",
                                                    )
                                                    .await;
                                                    continue 'conn;
                                                }
                                            }
                                        } else {
                                            tokio::select! {
                                                connection_result = &mut connection_task.0 => {
                                                    match connection_result {
                                                        Ok(Ok(())) => debug!(addr = target.to_string(), "Remote closed the HTTP1 connection"),
                                                        Ok(Err(error)) => debug!(addr = target.to_string(), error = %error, "HTTP1 connection closed with an error"),
                                                        Err(error) => warn!(addr = target.to_string(), error = %error, "HTTP1 connection task failed"),
                                                    }
                                                    continue 'conn;
                                                }
                                                // Receive a message to send from the queue
                                                pending_request = req_rx.recv() => {
                                                    let Some(mut pending_request) = pending_request else {
                                                        return;
                                                    };
                                                    *pending_request.request.version_mut() = http::Version::HTTP_11;
                                                    msg_to_send = Some(pending_request);
                                                }
                                            }
                                        }
                                    }
                                }
                                Ok(Err(handshake_error)) => {
                                    Self::retry_http_connection(
                                        &mut msg_to_send,
                                        &mut nb_retry,
                                        max_retry,
                                        &resp_tx,
                                        FetcherError::Hyper(handshake_error, target.to_string()),
                                        &target,
                                        "HTTP1 handshake",
                                    )
                                    .await;
                                }
                                Err(_) => {
                                    Self::return_pending_http_error(
                                        &mut msg_to_send,
                                        &mut nb_retry,
                                        &resp_tx,
                                        Self::http_timeout_error(timeout, &target),
                                        &target,
                                        "HTTP1 handshake",
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        Self::retry_http_connection(
                            &mut msg_to_send,
                            &mut nb_retry,
                            max_retry,
                            &resp_tx,
                            FetcherError::Io(e),
                            &target,
                            "HTTP connection",
                        )
                        .await;
                    }
                    Err(_) => {
                        Self::return_pending_http_error(
                            &mut msg_to_send,
                            &mut nb_retry,
                            &resp_tx,
                            Self::http_timeout_error(timeout, &target),
                            &target,
                            "HTTP connection",
                        )
                        .await;
                    }
                }
            }
        })
    }
}
