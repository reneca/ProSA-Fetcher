use std::{convert::Infallible, future::ready};

use http::Request;
use http_body_util::combinators::BoxBody;
use hyper::{
    Response,
    body::{Bytes, Incoming},
};
use prosa::core::adaptor::Adaptor;

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
        + prosa_utils::msg::tvf::Tvf
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
        request_builder: http::request::Builder,
    ) -> Result<Request<BoxBody<Bytes, Infallible>>, FetcherError<M>>;

    /// Process http response
    fn process_http_response(
        &mut self,
        _response: Response<Incoming>,
    ) -> impl std::future::Future<Output = Result<FetchAction<M>, FetcherError<M>>> + Send {
        ready(Ok(FetchAction::None))
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
