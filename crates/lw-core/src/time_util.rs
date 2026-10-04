use crate::{Error, Result, TsMicros};
use time::format_description::well_known::Rfc3339;
use time::{format_description, OffsetDateTime};

/// Parse an RFC 3339 timestamp (e.g. `2019-03-19T23:34:25.000000Z`) to UTC micros.
pub fn parse_rfc3339_to_micros(s: &str) -> Result<TsMicros> {
    let odt = OffsetDateTime::parse(s, &Rfc3339)
        .map_err(|e| Error::Parse(format!("invalid timestamp '{s}': {e}")))?;
    let secs = odt.unix_timestamp();
    let micros = i64::from(odt.nanosecond()) / 1_000;
    secs.checked_mul(1_000_000)
        .and_then(|v| v.checked_add(micros))
        .ok_or_else(|| Error::Parse(format!("timestamp overflow: {s}")))
}

/// Format UTC micros as RFC 3339 with microsecond precision and `Z`.
pub fn format_rfc3339_micros(ts: TsMicros) -> Result<String> {
    let secs = ts.div_euclid(1_000_000);
    let micros = ts.rem_euclid(1_000_000) as u32;
    let nanos = micros * 1_000;
    let odt = OffsetDateTime::from_unix_timestamp(secs)
        .map_err(|e| Error::Parse(format!("invalid ts {ts}: {e}")))?
        .replace_nanosecond(nanos)
        .map_err(|e| Error::Parse(format!("invalid nanos for ts {ts}: {e}")))?;
    // Prefer explicit 6-digit fractional seconds for round-trip fidelity.
    // NOTE(spec-drift): time 0.3 deprecates `parse` in favor of versioned parsers.
    let fmt = format_description::parse_borrowed::<2>(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z",
    )
    .map_err(|e| Error::Parse(e.to_string()))?;
    odt.format(&fmt)
        .map_err(|e| Error::Parse(format!("format failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_micros() {
        let s = "2019-03-19T23:34:25.123456Z";
        let ts = parse_rfc3339_to_micros(s).unwrap();
        assert_eq!(format_rfc3339_micros(ts).unwrap(), s);
    }
}
