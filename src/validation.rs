//! Shared format checks: the TUI gives quick feedback; the server checks again.
use crate::{models::VoterInput, services::AppResult};
use chrono::{NaiveDate, Utc};
/// Trim a required field and reject empty, oversized or control-character input.
pub fn text(value: &str, label: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 200 || value.chars().any(char::is_control) {
        return Err(format!("{label} must contain 1-200 bytes without control characters.").into());
    }
    Ok(value.to_owned())
}
/// Validate and normalize an email; optionally allow an empty voter email.
pub fn email(value: &str, optional: bool) -> AppResult<String> {
    let value = value.trim().to_lowercase();
    if optional && value.is_empty() {
        return Ok(value);
    }
    let (local, domain) = value.split_once('@').ok_or("Email must contain one @.")?;
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || value.len() > 200
        || value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | ':'))
        || domain.contains('@')
    {
        return Err("Enter an email such as name@example.com.".into());
    }
    Ok(value)
}
/// Require 7–15 ASCII digits, with at most one leading country-code plus.
pub fn phone(value: &str) -> AppResult<String> {
    let value = value.trim();
    let digits = value.strip_prefix('+').unwrap_or(value);
    if !(7..=15).contains(&digits.len()) || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return Err("Phone needs 7-15 digits and an optional leading +.".into());
    }
    Ok(value.into())
}
/// Reject codes with an incorrect length or non-ASCII digits.
pub fn digits(value: &str, length: usize, label: &str) -> AppResult<()> {
    if value.len() != length || !value.bytes().all(|c| c.is_ascii_digit()) {
        return Err(format!("{label} must contain exactly {length} digits.").into());
    }
    Ok(())
}
/// Check password size/control characters; apply minimum length at signup.
pub fn password(value: &str, signup: bool) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 72
        || value.chars().any(char::is_control)
        || (signup && value.len() < 10)
    {
        return Err(
            "Password needs 10 or more bytes at signup, at most 72, and no control characters."
                .into(),
        );
    }
    Ok(())
}
/// Validate identity fields and a real, non-future birth date; return normalized data.
pub fn voter_fields(input: &VoterInput) -> AppResult<VoterInput> {
    let dob = NaiveDate::parse_from_str(input.dob.trim(), "%Y-%m-%d")
        .map_err(|_| "DOB must be YYYY-MM-DD and a real date.")?;
    if dob > Utc::now().date_naive() || dob < NaiveDate::from_ymd_opt(1900, 1, 1).unwrap() {
        return Err("DOB must be between 1900-01-01 and today.".into());
    }
    Ok(VoterInput {
        full_name: text(&input.full_name, "Full name")?,
        dob: dob.to_string(),
        nid: text(&input.nid, "NID")?.to_uppercase(),
        phone: phone(&input.phone)?,
        email: email(&input.email, true)?,
    })
}

/// Require an adult after validating the supplied identity fields.
pub fn voter(input: &VoterInput) -> AppResult<VoterInput> {
    let input = voter_fields(input)?;
    let dob = NaiveDate::parse_from_str(&input.dob, "%Y-%m-%d")?;
    adult_on(
        dob,
        Utc::now()
            .with_timezone(&chrono_tz::America::New_York)
            .date_naive(),
    )?;
    Ok(input)
}

/// Calendar-age check, shared by enrollment and the final voting transaction.
pub fn adult_on(dob: NaiveDate, today: NaiveDate) -> AppResult<()> {
    if today.years_since(dob).unwrap_or(0) < 18 {
        return Err("Voters must be at least 18 years old.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eighteenth_birthday_boundary_and_leap_day() {
        let d = |s| NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap();
        assert!(adult_on(d("2008-10-20"), d("2026-10-19")).is_err());
        assert!(adult_on(d("2008-10-19"), d("2026-10-19")).is_ok());
        assert!(adult_on(d("2008-10-18"), d("2026-10-19")).is_ok());
        assert!(adult_on(d("2008-02-29"), d("2026-02-28")).is_err());
        assert!(adult_on(d("2008-02-29"), d("2026-03-01")).is_ok());
    }
    #[test]
    fn rejects_malformed_and_oversized_fields() {
        for bad in [
            "",
            "@",
            "a@",
            "a@@b.com",
            "a@b",
            "../a@b.com",
            "a@b.com\nInjected",
            "a b@c.com",
        ] {
            assert!(email(bad, false).is_err(), "accepted {bad:?}");
        }
        for bad in [
            "",
            "+",
            "123",
            "++1234567",
            "123+45678",
            "1234567890123456",
            "abcdefghi",
        ] {
            assert!(phone(bad).is_err());
        }
        for bad in ["", "12345", "1234567", "１２３４５６", "12345x"] {
            assert!(digits(bad, 6, "OTP").is_err());
        }
        assert!(text(&"a".repeat(201), "Name").is_err());
        assert!(text("a\x1bb", "Name").is_err());
        assert!(password("short", true).is_err());
        assert!(password(&"x".repeat(73), false).is_err());
        assert!(email("student@example.com", false).is_ok());
        assert!(phone("+15551234567").is_ok());
    }
    #[test]
    fn rejects_impossible_future_and_out_of_range_birth_dates() {
        let mut input = VoterInput {
            full_name: "Voter".into(),
            dob: "2000-02-29".into(),
            nid: "ID-1".into(),
            phone: "+15551234567".into(),
            email: "".into(),
        };
        assert!(voter(&input).is_ok());
        for bad in [
            "2001-02-29",
            "2000-13-01",
            "1899-12-31",
            "2999-01-01",
            "not a date",
        ] {
            input.dob = bad.into();
            assert!(voter(&input).is_err());
        }
    }
}
