use std::{convert::Infallible, future::ready};

use http::Request;
use http_body_util::combinators::BoxBody;
use hyper::{
    Response,
    body::{Bytes, Incoming},
};
use prosa::io::stream::{Stream, TargetSetting};
use prosa::{core::adaptor::Adaptor, tracing::warn};

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

    /// Process a message received on a subscription of the MQTT session.
    ///
    /// # MQTT session
    ///
    /// The adaptor can receive data pushed by an MQTT broker, alongside its periodic fetches.
    /// The broker, the credentials and the topics are not processor settings. The adaptor provides them at runtime in an
    /// [`MqttSession`](crate::mqtt::MqttSession), because they are often known only after an HTTP request (credentials, device list, ...).
    ///
    /// 1. The adaptor returns [`FetchAction::Mqtt`] from any method that returns a [`FetchAction`]:
    ///    [`fetch`](Self::fetch), [`process_http_response`](Self::process_http_response), this method, ...
    /// 2. The processor connects to the session `target`. It subscribes to every topic filter of the session
    ///    `subscriptions`, each with its QoS.
    /// 3. Once the broker acknowledges the subscriptions, [`process_mqtt_event`](Self::process_mqtt_event) receives
    ///    [`MqttEvent::Connected`](crate::mqtt::MqttEvent::Connected).
    /// 4. Every message published on a subscribed topic calls this method with the message topic and its raw payload.
    ///    The topic is the one of the message, not the filter: `/device/5678/status` for the `/device/+/status` filter.
    /// 5. When the connection is lost, the processor reconnects and subscribes again by itself.
    ///    It notifies [`process_mqtt_event`](Self::process_mqtt_event) with
    ///    [`MqttEvent::Disconnected`](crate::mqtt::MqttEvent::Disconnected), then `Connected` again.
    ///
    /// To change the topics or the credentials, return a new session: it replaces the current one.
    /// The session ends when the broker refuses it ([`MqttEvent::Refused`](crate::mqtt::MqttEvent::Refused)),
    /// when the active period ends ([`end_active_period`](Self::end_active_period)), or when the processor stops.
    ///
    /// The returned action is executed like any other: an HTTP or TCP action waits for the pending request, if any.
    /// An error is logged and doesn't affect the session.
    ///
    /// ```
    /// use bytes::Bytes;
    /// use prosa::{core::adaptor::Adaptor, io::stream::TargetSetting, tracing::info};
    /// use prosa_fetcher::{
    ///     adaptor::FetcherAdaptor,
    ///     mqtt::{MqttEvent, MqttSession, QoS},
    ///     proc::{FetchAction, FetcherError, FetcherProc},
    /// };
    /// use prosa_utils::msg::simple_string_tvf::SimpleStringTvf;
    /// use url::Url;
    ///
    /// struct PushAdaptor {
    ///     /// An MQTT session is open
    ///     session_open: bool,
    /// }
    ///
    /// impl Adaptor for PushAdaptor {
    ///     fn terminate(&self) {}
    /// }
    ///
    /// impl FetcherAdaptor<SimpleStringTvf> for PushAdaptor {
    ///     fn new(_proc: &FetcherProc<SimpleStringTvf>) -> Result<Self, FetcherError<SimpleStringTvf>> {
    ///         Ok(PushAdaptor { session_open: false })
    ///     }
    ///
    ///     fn fetch(&mut self) -> Result<FetchAction<SimpleStringTvf>, FetcherError<SimpleStringTvf>> {
    ///         if self.session_open {
    ///             // Data is pushed over MQTT, nothing to fetch on this tick
    ///             return Ok(FetchAction::None);
    ///         }
    ///
    ///         self.session_open = true;
    ///         let url = Url::parse("mqtts://broker.example.com:8883")
    ///             .map_err(|error| FetcherError::Other(format!("Invalid MQTT broker URL: {error}")))?;
    ///         Ok(FetchAction::Mqtt(Box::new(MqttSession {
    ///             target: TargetSetting::from(url),
    ///             client_id: "account_fetcher".to_string(),
    ///             username: Some("account".to_string()),
    ///             password: Some("password".to_string()),
    ///             // Topic filters to subscribe to, with the `+` and `#` MQTT wildcards
    ///             subscriptions: vec![
    ///                 ("/device/1234/quota".to_string(), QoS::AtLeastOnce),
    ///                 ("/device/+/status".to_string(), QoS::AtMostOnce),
    ///             ],
    ///         })))
    ///     }
    ///
    ///     fn process_mqtt_message(
    ///         &mut self,
    ///         topic: &str,
    ///         payload: Bytes,
    ///     ) -> Result<FetchAction<SimpleStringTvf>, FetcherError<SimpleStringTvf>> {
    ///         info!(topic, size = payload.len(), "Data pushed by the device");
    ///         Ok(FetchAction::None)
    ///     }
    ///
    ///     fn process_mqtt_event(
    ///         &mut self,
    ///         event: MqttEvent<SimpleStringTvf>,
    ///     ) -> Result<FetchAction<SimpleStringTvf>, FetcherError<SimpleStringTvf>> {
    ///         if let MqttEvent::Refused(_) = event {
    ///             // The session stopped, open a new one on the next tick
    ///             self.session_open = false;
    ///         }
    ///         Ok(FetchAction::None)
    ///     }
    ///
    ///     fn end_active_period(&mut self) {
    ///         // The processor closed the session
    ///         self.session_open = false;
    ///     }
    /// }
    /// ```
    #[cfg(feature = "mqtt")]
    fn process_mqtt_message(
        &mut self,
        _topic: &str,
        _payload: Bytes,
    ) -> Result<FetchAction<M>, FetcherError<M>> {
        Ok(FetchAction::None)
    }

    /// Process a state change of the MQTT session opened with [`FetchAction::Mqtt`].
    /// See [`process_mqtt_message`](Self::process_mqtt_message) for the session flow.
    ///
    /// - [`Connected`](crate::mqtt::MqttEvent::Connected): the broker accepted the connection and acknowledged the subscriptions.
    ///   `rejected_subscriptions` lists the topic filters it refused; the other ones are active.
    /// - [`Disconnected`](crate::mqtt::MqttEvent::Disconnected): the connection failed or was lost. The session reconnects with a backoff
    ///   and is notified again only once it's `Connected`.
    /// - [`Refused`](crate::mqtt::MqttEvent::Refused): the broker refused the credentials, the client id or the protocol, and the session stopped.
    ///   Return a new [`FetchAction::Mqtt`] session, or an action that gets new credentials first (e.g. [`FetchAction::Http`]).
    #[cfg(feature = "mqtt")]
    fn process_mqtt_event(
        &mut self,
        _event: crate::mqtt::MqttEvent<M>,
    ) -> Result<FetchAction<M>, FetcherError<M>> {
        Ok(FetchAction::None)
    }

    /// Method called when active period has ended
    /// If a time range is not configured, this method is never call
    fn end_active_period(&mut self) {}
}
