use std::{convert::Infallible, future::ready};

use http::Request;
use http_body_util::combinators::BoxBody;
use hyper::{
    Response,
    body::{Bytes, Incoming},
};
use prosa::core::adaptor::Adaptor;
use prosa::io::stream::{Stream, TargetSetting};
use tracing::warn;

use crate::proc::{FetchAction, FetcherError, FetcherProc};

/// Trait adaptor for the Fetcher processor.
pub trait FetcherAdaptor<M>: Adaptor
where
    M: 'static
        + std::marker::Send
        + std::marker::Sync
        + std::marker::Sized
        + std::clone::Clone
        + std::fmt::Debug
        + prosa::core::msg::Tvf
        + std::default::Default,
{
    /// Method called when the processor spawns
    /// This method is called only once so the processing will be thread safe
    fn new(proc: &FetcherProc<M>) -> Result<Self, FetcherError<M>>
    where
        Self: std::marker::Sized;

    /// Method that indicate what should be done to fetch informations from the remote system
    fn fetch(&mut self) -> Result<FetchAction<M>, FetcherError<M>>;

    /// Create an HTTP request to fetch information
    fn create_http_request(
        &self,
        _request_builder: http::request::Builder,
    ) -> Result<Request<BoxBody<Bytes, Infallible>>, FetcherError<M>> {
        Err(FetcherError::Other(
            "HTTP is unsupported by this adaptor".into(),
        ))
    }

    /// Create a TCP request for the configured target.
    fn create_tcp_request(&self, _target: &TargetSetting) -> Result<Bytes, FetcherError<M>> {
        Err(FetcherError::Other(
            "TCP is unsupported by this adaptor".into(),
        ))
    }

    /// Process http response
    fn process_http_response(
        &mut self,
        response: Result<Response<Incoming>, FetcherError<M>>,
    ) -> impl std::future::Future<Output = Result<FetchAction<M>, FetcherError<M>>> + Send {
        if let Err(e) = response {
            warn!("Wrong HTTP response: {:?}", e);
            ready(Err(e))
        } else {
            ready(Ok(FetchAction::None))
        }
    }

    /// Process a TCP stream after the request has been written.
    fn process_tcp_response(
        &mut self,
        _target: &TargetSetting,
        response: Result<Stream, FetcherError<M>>,
    ) -> impl std::future::Future<Output = Result<FetchAction<M>, FetcherError<M>>> + Send {
        ready(response.map(|_| FetchAction::None))
    }

    /// Process service response
    fn process_service_response(
        &mut self,
        _response: prosa::core::msg::ResponseMsg<M>,
    ) -> Result<FetchAction<M>, FetcherError<M>> {
        Ok(FetchAction::None)
    }

    /// Method to process incomings error received by the processor
    fn process_service_error(
        &self,
        _error: prosa::core::msg::ErrorMsg<M>,
    ) -> Result<FetchAction<M>, FetcherError<M>> {
        Ok(FetchAction::None)
    }

    /// Method called when active period has ended
    /// If a time range is not configured, this method is never call
    fn end_active_period(&mut self) {}
}
