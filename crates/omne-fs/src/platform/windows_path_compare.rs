use std::cmp::Ordering;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

// DESIGN INVARIANT (Windows OsStr comparison):
// - We must compare `OsStr` directly under Windows path semantics without lossy UTF-8 conversion.
// - std does not provide a locale-invariant, case-insensitive comparator for `OsStr`/`Path`.
// - ASCII lowercasing is insufficient for non-ASCII path components.
// - `CompareStringOrdinal(..., ignore_case=1)` performs ordinal, case-insensitive UTF-16 comparison
//   on Windows-native code units and preserves lexical boundary semantics.
//
// SAFETY:
// - Rust has no native declaration for this Win32 API, so we must declare the foreign symbol.
// - The unsafety at this item is the FFI ABI boundary itself; call sites still have to provide
//   valid pointers and lengths, which are documented where the function is invoked.
#[link(name = "Kernel32")]
unsafe extern "system" {
    #[link_name = "CompareStringOrdinal"]
    fn compare_string_ordinal(
        string1: *const u16,
        count1: i32,
        string2: *const u16,
        count2: i32,
        ignore_case: i32,
    ) -> i32;
}

pub(crate) fn os_str_eq_case_insensitive(a: &OsStr, b: &OsStr) -> bool {
    os_str_cmp_case_insensitive(a, b) == Ordering::Equal
}

pub(crate) fn os_str_cmp_case_insensitive(a: &OsStr, b: &OsStr) -> Ordering {
    const CSTR_LESS_THAN: i32 = 1;
    const CSTR_EQUAL: i32 = 2;
    const CSTR_GREATER_THAN: i32 = 3;

    // Fast path: exact `OsStr` equality avoids UTF-16 allocations and FFI call.
    if a == b {
        return Ordering::Equal;
    }

    // Fast path: ASCII-only case-insensitive ordering without allocations.
    // Falls back when non-ASCII code units differ and require Windows ordinal rules.
    if let Some(ordering) = ascii_case_insensitive_cmp_fast(a, b) {
        return ordering;
    }

    let a_wide: Vec<u16> = a.encode_wide().collect();
    let b_wide: Vec<u16> = b.encode_wide().collect();
    let Ok(a_len) = i32::try_from(a_wide.len()) else {
        return fallback_os_str_ordering(a, b);
    };
    let Ok(b_len) = i32::try_from(b_wide.len()) else {
        return fallback_os_str_ordering(a, b);
    };

    let a_ptr = if a_wide.is_empty() {
        ptr::null()
    } else {
        a_wide.as_ptr()
    };
    let b_ptr = if b_wide.is_empty() {
        ptr::null()
    } else {
        b_wide.as_ptr()
    };

    // SAFETY:
    // - `a_ptr`/`b_ptr` are null for empty strings or valid UTF-16 buffers for the given lengths.
    // - `a_wide`/`b_wide` live across the call and pointers do not escape.
    // - `ignore_case = 1` requests ordinal, case-insensitive comparison.
    match unsafe { compare_string_ordinal(a_ptr, a_len, b_ptr, b_len, 1) } {
        CSTR_LESS_THAN => Ordering::Less,
        CSTR_EQUAL => Ordering::Equal,
        CSTR_GREATER_THAN => Ordering::Greater,
        _ => fallback_os_str_ordering(a, b),
    }
}

fn fallback_os_str_ordering(a: &OsStr, b: &OsStr) -> Ordering {
    a.encode_wide().cmp(b.encode_wide())
}

#[inline]
fn lower_ascii_u16(unit: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&unit) {
        unit + 32
    } else {
        unit
    }
}

// Returns:
// - `Some(Ordering)` when ASCII-only comparison is conclusive.
// - `None` when non-ASCII differences require Windows ordinal comparison.
fn ascii_case_insensitive_cmp_fast(a: &OsStr, b: &OsStr) -> Option<Ordering> {
    let mut a_iter = a.encode_wide();
    let mut b_iter = b.encode_wide();

    loop {
        match (a_iter.next(), b_iter.next()) {
            (None, None) => return Some(Ordering::Equal),
            (Some(_), None) => return Some(Ordering::Greater),
            (None, Some(_)) => return Some(Ordering::Less),
            (Some(a_unit), Some(b_unit)) => {
                if a_unit == b_unit {
                    continue;
                }
                if a_unit <= 0x7f && b_unit <= 0x7f {
                    let a_lower = lower_ascii_u16(a_unit);
                    let b_lower = lower_ascii_u16(b_unit);
                    if a_lower == b_lower {
                        continue;
                    }
                    return Some(a_lower.cmp(&b_lower));
                }
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::ascii_case_insensitive_cmp_fast;

    #[test]
    fn ascii_fast_cmp_matches_case_insensitive_expectations() {
        assert_eq!(
            ascii_case_insensitive_cmp_fast(OsStr::new("Alpha"), OsStr::new("alpha")),
            Some(std::cmp::Ordering::Equal)
        );
        assert_eq!(
            ascii_case_insensitive_cmp_fast(OsStr::new("alpha"), OsStr::new("beta")),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(
            ascii_case_insensitive_cmp_fast(OsStr::new("beta"), OsStr::new("Alpha")),
            Some(std::cmp::Ordering::Greater)
        );
    }

    #[test]
    fn ascii_fast_cmp_falls_back_for_non_ascii_differences() {
        assert_eq!(
            ascii_case_insensitive_cmp_fast(OsStr::new("Ä"), OsStr::new("ä")),
            None
        );
    }

    #[test]
    fn ascii_fast_cmp_checks_later_chars_after_case_only_difference() {
        assert_eq!(
            ascii_case_insensitive_cmp_fast(OsStr::new("Ab"), OsStr::new("aC")),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(
            ascii_case_insensitive_cmp_fast(OsStr::new("safe"), OsStr::new("Saevil")),
            Some(std::cmp::Ordering::Greater)
        );
        assert_eq!(
            ascii_case_insensitive_cmp_fast(OsStr::new("A"), OsStr::new("aB")),
            Some(std::cmp::Ordering::Less)
        );
    }
}
