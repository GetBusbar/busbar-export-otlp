// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::ops::Deref;
use zeroize::Zeroize;

/// The URL parser owns a serialization separate from the operator's setting. Consume it through
pub(crate) struct ParsedUrl(Option<url::Url>);

impl ParsedUrl {
    pub(crate) fn parse(text: &str) -> Result<Self, url::ParseError> {
        url::Url::parse(text).map(|url| Self(Some(url)))
    }
}

impl Deref for ParsedUrl {
    type Target = url::Url;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("owned parsed URL")
    }
}
impl Drop for ParsedUrl {
    fn drop(&mut self) {
        if let Some(url) = self.0.take() {
            let mut text = String::from(url);
            text.zeroize();
        }
    }
}

/// Borrow-deserialize from the parse tree so every owned source string is still present to wipe
pub(crate) struct SettingsValue(pub(crate) serde_json::Value);
impl Deref for SettingsValue {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for SettingsValue {
    fn drop(&mut self) {
        fn wipe(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(text) => text.zeroize(),
                serde_json::Value::Array(items) => items.iter_mut().for_each(wipe),
                serde_json::Value::Object(items) => {
                    for (mut key, mut value) in std::mem::take(items) {
                        key.zeroize();
                        wipe(&mut value);
                    }
                }
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}
