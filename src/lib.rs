/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
#![deny(
    warnings,
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]

pub mod error;
mod keyring;

pub use keyring::*;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_peek_criteria_test() {
        for pair in &[
            ("", 0),
            ("kind=generic", 1),
            ("kind=internet,account=aws", 2),
            ("account=aws,service=lox", 2),
        ] {
            let criteria = parse_peek_criteria(pair.0);
            assert_eq!(criteria.len(), pair.1);
        }
    }
}
