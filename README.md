# ProSA Fetcher

[ProSA](https://github.com/worldline/ProSA) processor to fetch information from remote systems.

The main goal of this processor is to retrieve metrics periodically from remote systems.

## Configuration

For configuration, you can set either the `target`, or the `service_name` (or both), depending on your fetcher type.

The `target` uses ProSA's [`TargetSetting`](https://docs.rs/prosa/latest/prosa/io/stream/struct.TargetSetting.html) to define all connection information. HTTP adaptors create HTTP requests; TCP adaptors create a byte request and read the response stream until their protocol's end marker.
If you need to authenticate, you will have to set the user and password in the [url](https://docs.rs/url/latest/url/struct.Url.html#method.password).

If you want to fetch an internal service, you only have to specify its name with `service_name`.

An `auth_method` can also be set (not present in the following example), but generally, the auth method is known by the adaptor and will be set by it.

The last two parameters, `period` and `timeout`, configure the interval between fetches and the timeout for each fetch, respectively.
The timeout should be less than the period. If a fetch runs past the next tick, the fetcher coalesces overlapping ticks and starts at most one follow-up fetch.

```yaml
fetcher:
  target:
    url: "http://localhost"
  service_name: "output_service"
  period:
    secs: 60
    nanos: 0
  timeout:
    secs: 10
    nanos: 0
```

If you want to exclude a time range, you can use the `active_time_range` option to only fetch during a specif hour time range.
From the start to the end hour of the day.
```yaml
fetcher:
  <...>
  active_time_range:
    start: "06:00:00"
    end: "23:00:00"
```

## MQTT sessions

With the `mqtt` cargo feature, an adaptor can return `FetchAction::Mqtt(session)` to open an MQTT 3.1.1 client session that receives pushed messages.
The session gives the broker `target` (`mqtts://` or any ProSA SSL scheme for TLS), the client id, the credentials and the subscriptions.
It uses a clean session, renews the subscriptions on every reconnection, and runs alongside the periodic fetches.
A new session replaces the current one. The session closes when the processor stops or when the active time range ends.

Messages go to `FetcherAdaptor::process_mqtt_message`, and connection changes go to `FetcherAdaptor::process_mqtt_event`:

- `Connected` once the broker acknowledges the subscriptions.
- `Disconnected` when the connection fails or is lost. The session reconnects with an exponential backoff.
- `Refused` when the broker rejects the credentials, the client id or the protocol. The session stops, and the adaptor can return a new session, for example after refreshing its credentials over HTTP.

Both callbacks return a `FetchAction`. HTTP and TCP actions follow the same one-request-in-flight rule as the periodic fetches.

```yaml
fetcher:
  <...>
  mqtt:
    keep_alive:
      secs: 60
      nanos: 0
    max_packet_size: 65536
    reconnect_min:
      secs: 1
      nanos: 0
    reconnect_max:
      secs: 60
      nanos: 0
```

All `mqtt` settings are optional and default to the values above. A packet larger than `max_packet_size` closes the connection.
`timeout` bounds the CONNACK and SUBACK waits and every write. `reconnect_min` must be greater than zero.
On a configuration reload, a change of the `mqtt` settings reconnects the current session. A `timeout` change applies from the next session.

## Fetch failures and metrics

A failed fetch does not stop the processor. The worker applies `timeout` and
`max_retry` to the current request, reports the final failure, and the
processor tries again on the next scheduled tick. Internal processor and
worker-channel failures remain fatal.

The fetcher exports two metrics:

- `prosa_fetcher_status_code` is a gauge containing the latest
  HTTP-compatible result code. HTTP responses keep their exact status. A non-2xx
  HTTP response that the adaptor answers with a follow-up HTTP or TCP request
  (e.g. an authentication challenge) is neither recorded nor logged as a
  failure. Other
  transports use `200` for success, `400` for invalid input, `401` for invalid
  credentials, `403` for permission failures, `502` for protocol or broken
  connection failures, `503` for unavailable targets or services, `504` for
  timeouts, and `500` for other adaptor failures.
- `prosa_fetcher_duration` records successful fetch durations in milliseconds.
  Failed attempts are not added to this histogram and it has no success/error
  result attribute.

With the `mqtt` feature, the fetcher also exports:

- `prosa_fetcher_mqtt_connected`, a gauge set to `1` while the MQTT session
  is connected and `0` otherwise.
- `prosa_fetcher_mqtt_messages`, a counter of the MQTT messages received.

Outside `active_time_range`, no request is made and the status gauge retains
its last observed value.
