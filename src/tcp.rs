use std::{io, marker::PhantomData, time::Duration};

use bytes::Bytes;
use prosa::io::stream::{Stream, TargetSetting};
use tokio::{io::AsyncWriteExt as _, sync::mpsc, time};
use tracing::warn;

use crate::proc::FetcherError;

pub(super) struct PendingRequest {
    pub request: Bytes,
    pub started_at: time::Instant,
    pub deadline: time::Instant,
}

pub(super) struct FetchResult<M: Send> {
    pub response: Result<Stream, FetcherError<M>>,
    pub started_at: time::Instant,
    pub deadline: time::Instant,
    pub _marker: PhantomData<M>,
}

pub(super) fn timeout_error<M: Send>(timeout: Duration, target: &TargetSetting) -> FetcherError<M> {
    FetcherError::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("TCP timeout after {timeout:?} while fetching from `{target}`"),
    ))
}

pub(super) fn spawn<M: Send + 'static>(
    target: TargetSetting,
    timeout: Duration,
    max_retry: u8,
    mut req_rx: mpsc::Receiver<PendingRequest>,
    resp_tx: mpsc::Sender<FetchResult<M>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(pending) = req_rx.recv().await {
            let mut retries = 0;
            let response = loop {
                let stream = match time::timeout_at(pending.deadline, target.connect()).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error))
                        if retries < max_retry && time::Instant::now() < pending.deadline =>
                    {
                        retries += 1;
                        warn!(addr = %target, %error, "TCP connection failed; retry {retries}/{max_retry}");
                        continue;
                    }
                    Ok(Err(error)) => break Err(FetcherError::Io(error)),
                    Err(_) => break Err(timeout_error(timeout, &target)),
                };

                let mut stream = stream;
                break match time::timeout_at(pending.deadline, stream.write_all(&pending.request))
                    .await
                {
                    Ok(Ok(())) => Ok(stream),
                    Ok(Err(error)) => Err(FetcherError::Io(error)),
                    Err(_) => Err(timeout_error(timeout, &target)),
                };
            };

            if resp_tx
                .send(FetchResult {
                    response,
                    started_at: pending.started_at,
                    deadline: pending.deadline,
                    _marker: PhantomData,
                })
                .await
                .is_err()
            {
                return;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use prosa_utils::msg::simple_string_tvf::SimpleStringTvf;
    use tokio::net::TcpListener;
    use url::Url;

    #[tokio::test]
    async fn reports_connection_failure_after_retries() {
        time::timeout(Duration::from_secs(1), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            drop(listener);
            let target = TargetSetting::from(Url::parse(&format!("tcp://{addr}/ups")).unwrap());
            let (req_tx, req_rx) = mpsc::channel(1);
            let (resp_tx, mut resp_rx) = mpsc::channel(1);
            let worker = spawn::<SimpleStringTvf>(target, Duration::from_millis(200), 2, req_rx, resp_tx);
            let started_at = time::Instant::now();
            req_tx.send(PendingRequest {
                request: Bytes::from_static(b"LIST VAR ups\n"),
                started_at,
                deadline: started_at + Duration::from_millis(200),
            }).await.unwrap();
            let result = resp_rx.recv().await.unwrap();
            assert!(matches!(result.response, Err(FetcherError::Io(error)) if error.kind() == io::ErrorKind::ConnectionRefused));
            worker.abort();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn write_obeys_one_request_deadline() {
        time::timeout(Duration::from_secs(2), async {
            let request = Bytes::from(vec![b'x'; 16 * 1024 * 1024]);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (_socket, _) = listener.accept().await.unwrap();
                time::sleep(Duration::from_secs(1)).await;
            });
            let target = TargetSetting::from(Url::parse(&format!("tcp://{addr}/ups")).unwrap());
            let (req_tx, req_rx) = mpsc::channel(1);
            let (resp_tx, mut resp_rx) = mpsc::channel(1);
            let worker = spawn::<SimpleStringTvf>(target, Duration::from_millis(30), 2, req_rx, resp_tx);
            let started_at = time::Instant::now();
            req_tx.send(PendingRequest {
                request,
                started_at,
                deadline: started_at + Duration::from_millis(30),
            }).await.unwrap();
            let result = resp_rx.recv().await.unwrap();
            assert!(matches!(result.response, Err(FetcherError::Io(error)) if error.kind() == io::ErrorKind::TimedOut));
            worker.abort();
            server.abort();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn does_not_retry_after_write_failure() {
        time::timeout(Duration::from_secs(2), async {
            let request = Bytes::from(vec![b'x'; 16 * 1024 * 1024]);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                drop(socket);
                assert!(time::timeout(Duration::from_millis(100), listener.accept()).await.is_err(), "a write failure must not reconnect");
            });
            let target = TargetSetting::from(Url::parse(&format!("tcp://{addr}/ups")).unwrap());
            let (req_tx, req_rx) = mpsc::channel(1);
            let (resp_tx, mut resp_rx) = mpsc::channel(1);
            let worker = spawn::<SimpleStringTvf>(target, Duration::from_secs(1), 2, req_rx, resp_tx);
            let started_at = time::Instant::now();
            req_tx.send(PendingRequest {
                request,
                started_at,
                deadline: started_at + Duration::from_secs(1),
            }).await.unwrap();
            let result = resp_rx.recv().await.unwrap();
            assert!(matches!(result.response, Err(FetcherError::Io(error)) if error.kind() != io::ErrorKind::TimedOut));
            server.await.unwrap();
            worker.abort();
        }).await.unwrap();
    }
}
