# ProSA Fetcher

[ProSA](https://github.com/worldline/ProSA) processor to fetch information from remote systems.

The main goal of this processor is to retrieve metrics periodically from remote systems.

## Configuration

For configuration, you can set either the `target`, or the `service_name` (or both), depending on your fetcher type.

The `target` uses ProSA's [`TargetSetting`](https://docs.rs/prosa/latest/prosa/io/stream/struct.TargetSetting.html) to define all connection information.
If you need to authenticate, you will have to set the user and password in the [url](https://docs.rs/url/latest/url/struct.Url.html#method.password).

If you want to fetch an internal service, you only have to specify its name with `service_name`.

An `auth_method` can also be set (not present in the following example), but generally, the auth method is known by the adaptor and will be set by it.

The last two parameters, `period` and `timeout`, configure the interval between fetches and the timeout for each fetch, respectively.
The timeout should be less than the period to ensure that only one fetch runs at a time.

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
