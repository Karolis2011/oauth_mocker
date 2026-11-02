//! Built-in presets: config layers that make the mock behave like a known provider.

/// Name and TOML text of every preset. A preset sets behavior only, never keys, clients or users.
const PRESETS: &[(&str, &str)] = &[
    ("google", include_str!("../presets/google.toml")),
    ("okta", include_str!("../presets/okta.toml")),
];

pub fn get(name: &str) -> Option<&'static str> {
    PRESETS.iter().find(|(n, _)| *n == name).map(|(_, text)| *text)
}

pub fn names() -> Vec<&'static str> {
    PRESETS.iter().map(|(name, _)| *name).collect()
}

/// Layers `top` over `base`: tables merge key by key, any other value in `top` replaces.
pub fn merge(base: &mut toml::Table, top: toml::Table) {
    for (key, value) in top {
        match (base.get_mut(&key), value) {
            (Some(toml::Value::Table(base)), toml::Value::Table(top)) => merge(base, top),
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_merge_and_other_values_replace() {
        let mut base: toml::Table = "a = 1\nlist = [1, 2]\n[t]\nx = 1\ny = 1".parse().unwrap();
        merge(&mut base, "list = [3]\n[t]\ny = 2\nz = 3".parse().unwrap());
        let expected: toml::Table = "a = 1\nlist = [3]\n[t]\nx = 1\ny = 2\nz = 3".parse().unwrap();
        assert_eq!(base, expected);
    }

    #[test]
    fn presets_hold_behavior_only() {
        for name in names() {
            let table: toml::Table = get(name).unwrap().parse().unwrap();
            for key in ["preset", "keys", "clients", "users", "issuer"] {
                assert!(!table.contains_key(key), "preset `{name}` sets `{key}`");
            }
        }
    }
}
