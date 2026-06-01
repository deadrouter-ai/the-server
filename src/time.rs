//! Minimal time helper module for parsing HTTP date headers.

pub fn parse_http_date(date_str: &str) -> Option<u64> {
    // Expected format: "Mon, 01 Jun 2026 12:41:36 GMT"
    let mut parts = date_str.split_whitespace();
    let _day_name = parts.next()?; // "Mon,"
    let day_str = parts.next()?; // "01"
    let month_str = parts.next()?; // "Jun"
    let year_str = parts.next()?; // "2026"
    let time_str = parts.next()?; // "12:41:36"

    let day = day_str.parse::<u64>().ok()?;
    let year = year_str.parse::<u64>().ok()?;

    let month = match month_str {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };

    let mut time_parts = time_str.split(':');
    let hour = time_parts.next()?.parse::<u64>().ok()?;
    let minute = time_parts.next()?.parse::<u64>().ok()?;
    let second = time_parts.next()?.parse::<u64>().ok()?;

    // Convert to Unix timestamp
    let mut days = 0;
    for y in 1970..year {
        if is_leap_year(y) {
            days += 366;
        } else {
            days += 365;
        }
    }

    let month_days = if is_leap_year(year) {
        [0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    for m in 1..month {
        days += month_days[m as usize];
    }
    days += day - 1;

    let timestamp = days * 86400 + hour * 3600 + minute * 60 + second;
    Some(timestamp)
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}
