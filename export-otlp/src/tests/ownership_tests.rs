use super::*;
use crate::wipe_probe::{watch, Probe};

#[test]
fn endpoint_and_settings_destroy_their_owned_credential_copies() {
    let probe = Probe::start();
    let settings = OtlpSettings {
        url: "https://operator:password-canary@collector.example/private-canary?key=query-canary"
            .into(),
    };
    watch("settings url", settings.url.as_bytes());
    let endpoint = door::Endpoint::of(&settings);
    assert!(endpoint.target.authorization.is_some());
    watch("collector", endpoint.collector.as_bytes());
    watch("request target", endpoint.target.path.as_bytes());
    for part in &endpoint.secrets {
        watch("redaction part", part.as_bytes());
    }
    let masked = scrub("password-canary query-canary", &endpoint.secrets);
    assert!(!masked.contains("password-canary"));
    drop(endpoint);
    drop(settings);
    probe.finish().assert_wiped_on_linux(&[
        "settings url",
        "request target",
        "redaction part",
        "parsed url",
        "Basic value",
    ]);
}

#[test]
fn a_partly_deserialized_settings_url_is_wiped_on_refusal() {
    let probe = Probe::start();
    let result = <door::Otlp as busbar_contract::abi::sdk::life::Life>::validate(
        br#"{"url":"https://operator:refused-canary@collector.example/","zz_unknown":true}"#,
    );
    assert!(result.is_err());
    drop(result);
    probe
        .finish()
        .assert_wiped_on_linux(&["decoded settings url", "settings JSON"]);
}

pub(super) fn watch_settings_value(value: &serde_json::Value) {
    match value {
        serde_json::Value::String(text) => watch("settings JSON", text.as_bytes()),
        serde_json::Value::Array(values) => values.iter().for_each(watch_settings_value),
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                watch("settings JSON", key.as_bytes());
                watch_settings_value(value);
            }
        }
        _ => {}
    }
}

#[test]
fn removing_userinfo_keeps_the_parsers_existing_serialized_destination() {
    for text in [
        "HTTP://op%40er:pass%3Aword@[2001:db8::1]:80/a/../b%2Fc?q=one%2Ftwo#frag",
        "https://operator:password@bücher.example:443/a?x=%FF#section",
        "ftp://:password@files.example:21/a%2Fb",
        "https://operator@receiver.example/",
        "custom://operator:password@receiver.example:8123/path?key=value",
    ] {
        let mut previous = url::Url::parse(text).expect("valid credential URL");
        previous.set_username("").expect("userinfo can be removed");
        previous
            .set_password(None)
            .expect("password can be removed");
        let (clean, authorization) = split_credentials(text);
        assert_eq!(clean, previous.as_str(), "{text}");
        assert!(
            authorization.is_some(),
            "the same Basic credential is still produced"
        );
    }
}
