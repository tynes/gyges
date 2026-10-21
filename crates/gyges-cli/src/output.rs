//! `--json` output: the response message as proto3 JSON plus
//! `schema_version` (API.md §5).

use serde_json::{Map, Value};

use crate::exit::CliError;

/// Serialise `value` and add `"schema_version"`. Streaming RPCs call this
/// once per element, giving one object per line.
pub fn to_json<T: serde::Serialize>(value: &T) -> Result<String, CliError> {
    let v = serde_json::to_value(value)?;
    let mut map = match v {
        Value::Object(map) => map,
        other => {
            let mut map = Map::new();
            map.insert("value".into(), other);
            map
        }
    };
    map.insert(
        "schema_version".into(),
        Value::String(gyges_proto::schema_version().into()),
    );
    Ok(serde_json::to_string(&Value::Object(map))?)
}

/// `{"schema_version": …, "error": <GygesError>}`.
pub fn error_json(err: &CliError) -> String {
    let error = serde_json::to_value(err.as_gyges_error()).unwrap_or(Value::Null);
    let mut map = Map::new();
    map.insert(
        "schema_version".into(),
        Value::String(gyges_proto::schema_version().into()),
    );
    map.insert("error".into(), error);
    Value::Object(map).to_string()
}

/// Unix seconds as RFC 3339, for human output.
pub fn format_unix(secs: i64) -> String {
    match u64::try_from(secs) {
        Ok(s) => humantime::format_rfc3339_seconds(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(s),
        )
        .to_string(),
        Err(_) => secs.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gyges_proto::v1::{ApiVersion, GetInfoResponse};

    #[test]
    fn schema_version_is_added_at_the_top_level() {
        let info = GetInfoResponse {
            api_version: Some(ApiVersion { major: 0, minor: 1 }),
            ..Default::default()
        };
        let s = to_json(&info).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["schema_version"], gyges_proto::schema_version());
        assert_eq!(v["api_version"]["minor"], 1);
    }

    #[test]
    fn empty_messages_still_carry_schema_version() {
        let s = to_json(&gyges_proto::v1::ShutdownResponse {}).unwrap();
        assert_eq!(
            s,
            format!(
                "{{\"schema_version\":\"{}\"}}",
                gyges_proto::schema_version()
            )
        );
    }

    #[test]
    fn rfc3339_times() {
        assert_eq!(format_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix(-5), "-5");
    }
}
