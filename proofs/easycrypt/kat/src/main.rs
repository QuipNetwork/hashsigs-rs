// Copyright (C) 2026 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Write the known-answer tests of `hashsigs-rs` for the EasyCrypt
//! specification in `proofs/easycrypt/spec`.
//!
//! For every group of the in-crate catalog this program writes two files:
//!
//! - `<out>/vectors/<group>.json`: the inputs and outputs, for any implementation.
//! - `<out>/ec/Kat_<group>.ec`: the same cases as EasyCrypt lemmas.
//!
//! The specification keeps Keccak-256 abstract. Each EasyCrypt file defines a
//! lookup table that holds every Keccak call that the Rust code made for the
//! cases of the group, and clones the specification with that table in place
//! of the hash. A lemma then holds only if the specification makes the calls
//! that the Rust code made and combines the results in the same way.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hashsigs_rs::kat::{catalog, Group, Value};
use serde_json::{json, Map, Value as Json};

/// Children of one node of the lookup tree.
const FAN_OUT: usize = 8;
/// A group whose table is larger than this cannot be replayed in reasonable time.
const MAX_TABLE: usize = 20_000;

fn main() -> ExitCode {
    let mut out = None;
    let mut only = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match (arg.as_str(), args.next()) {
            ("--out", Some(dir)) => out = Some(PathBuf::from(dir)),
            ("--only", Some(name)) => only.push(name),
            _ => {
                eprintln!("usage: gen-kats --out DIR [--only GROUP]...");
                return ExitCode::FAILURE;
            }
        }
    }
    let Some(out) = out else {
        eprintln!("usage: gen-kats --out DIR [--only GROUP]...");
        return ExitCode::FAILURE;
    };
    let groups = catalog();
    let unknown: Vec<&String> = only
        .iter()
        .filter(|name| !groups.iter().any(|(group, _)| group == name))
        .collect();
    if !unknown.is_empty() {
        eprintln!("unknown group: {unknown:?}");
        return ExitCode::FAILURE;
    }
    for (name, build) in groups {
        if !only.is_empty() && !only.iter().any(|o| o == name) {
            continue;
        }
        let group = build();
        if let Err(message) = write_group(&group, &out) {
            eprintln!("{name}: {message}");
            return ExitCode::FAILURE;
        }
        println!(
            "{name}: {} cases, {} Keccak calls",
            group.cases.len(),
            group.trace.len()
        );
    }
    ExitCode::SUCCESS
}

/// Render a value as an EasyCrypt term.
fn ec(value: &Value) -> String {
    let join = |items: &[Value], sep: &str| items.iter().map(ec).collect::<Vec<_>>().join(sep);
    match value {
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Bytes(bytes) => {
            let items: Vec<String> = bytes.iter().map(u8::to_string).collect();
            format!("[{}]", items.join("; "))
        }
        Value::List(items) => format!("[{}]", join(items, "; ")),
        Value::Tuple(items) => format!("({})", join(items, ", ")),
        Value::Opt(None) => "None".into(),
        Value::Opt(Some(inner)) => format!("(Some {})", ec(inner)),
        Value::Record(fields) => {
            let fields: Vec<String> = fields
                .iter()
                .map(|(name, value)| format!("{name} = {}", ec(value)))
                .collect();
            format!("{{| {} |}}", fields.join("; "))
        }
        Value::Ctor(name, args) if args.is_empty() => (*name).into(),
        Value::Ctor(name, args) => format!("({name} {})", join(args, " ")),
    }
}

/// Render a value for the JSON vector file. Byte strings become hex.
fn js(value: &Value) -> Json {
    match value {
        Value::Bool(b) => json!(b),
        Value::Int(n) => json!(n),
        Value::Bytes(bytes) => json!(hex(bytes)),
        Value::List(items) | Value::Tuple(items) => Json::Array(items.iter().map(js).collect()),
        Value::Opt(None) => Json::Null,
        Value::Opt(Some(inner)) => js(inner),
        Value::Record(fields) => Json::Object(
            fields
                .iter()
                .map(|(name, value)| ((*name).to_string(), js(value)))
                .collect(),
        ),
        Value::Ctor(name, args) => {
            json!({ "constructor": name, "arguments": args.iter().map(js).collect::<Vec<_>>() })
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The table key of a hash input: the integer with the base-256 digits
/// `1, input[0], input[1], ...`, in decimal. The leading 1 keeps the key of
/// every input distinct.
fn key(input: &[u8]) -> String {
    let mut digits = vec![1u8];
    digits.extend_from_slice(input);
    // Repeated division by 10^9 of the base-256 number.
    let mut chunks = Vec::new();
    while digits.iter().any(|&d| d != 0) {
        let mut rem = 0u64;
        for d in digits.iter_mut() {
            let cur = (rem << 8) | u64::from(*d);
            *d = (cur / 1_000_000_000) as u8;
            rem = cur % 1_000_000_000;
        }
        chunks.push(rem);
        let first_nonzero = digits.iter().position(|&d| d != 0).unwrap_or(digits.len());
        digits.drain(..first_nonzero);
    }
    let mut out = chunks
        .pop()
        .map_or_else(|| "0".to_string(), |c| c.to_string());
    for chunk in chunks.iter().rev() {
        let _ = write!(out, "{chunk:09}");
    }
    out
}

/// Operators for the lookup table, and the term that reads it at `k`.
///
/// The table is a tree of small operators. One lookup unfolds one operator
/// per level, so its cost does not grow with the size of the table.
fn table(group: &Group) -> (String, String) {
    // Sorting by (length, bytes) is sorting by key.
    let mut entries: Vec<(&Vec<u8>, &[u8; 32])> = group.trace.iter().collect();
    entries.sort_by(|a, b| (a.0.len(), a.0).cmp(&(b.0.len(), b.0)));
    let keys: Vec<String> = entries.iter().map(|(input, _)| key(input)).collect();
    if entries.is_empty() {
        return (String::new(), "[]".into());
    }
    let mut operators = Vec::new();
    build(&entries, &keys, 0, entries.len(), &mut operators);
    let root = format!("kat_t{} k", operators.len() - 1);
    (operators.join("\n"), root)
}

fn decide(items: &[(String, String)], indent: usize) -> String {
    let pad = " ".repeat(indent);
    if items.len() == 1 {
        return format!("{pad}{}", items[0].1);
    }
    let mid = items.len() / 2;
    format!(
        "{pad}if k < {} then\n{}\n{pad}else\n{}",
        items[mid].0,
        decide(&items[..mid], indent + 2),
        decide(&items[mid..], indent + 2)
    )
}

fn build(
    entries: &[(&Vec<u8>, &[u8; 32])],
    keys: &[String],
    lo: usize,
    hi: usize,
    operators: &mut Vec<String>,
) -> (String, String) {
    let items: Vec<(String, String)> = if hi - lo <= FAN_OUT {
        (lo..hi)
            .map(|i| {
                let digest = ec(&Value::bytes(entries[i].1));
                (
                    keys[i].clone(),
                    format!("(if k = {} then {digest} else [])", keys[i]),
                )
            })
            .collect()
    } else {
        let step = (hi - lo).div_ceil(FAN_OUT);
        (lo..hi)
            .step_by(step)
            .map(|s| build(entries, keys, s, (s + step).min(hi), operators))
            .collect()
    };
    let name = format!("kat_t{}", operators.len());
    operators.push(format!(
        "op {name} (k : int) : int list =\n{}.\n",
        decide(&items, 2)
    ));
    (keys[lo].clone(), format!("{name} k"))
}

fn write_group(group: &Group, out: &Path) -> Result<(), String> {
    if group.trace.len() > MAX_TABLE {
        return Err(format!(
            "{} Keccak calls exceed {MAX_TABLE}",
            group.trace.len()
        ));
    }
    let (operators, root) = table(group);
    let bindings: Vec<String> = group
        .parameters
        .iter()
        .map(|(name, value)| format!("  op {name} <- {}", ec(value)))
        .collect();
    let mut text = String::new();
    let _ = writeln!(
        text,
        "(* Generated by proofs/easycrypt/kat (gen-kats). Do not edit. *)\n\
         require import AllCore List IntDiv.\n\
         require import Compute Search.\n\
         require Spec.\n\n\
         op kat_key (bs : int list) : int = foldl (fun acc b => acc * 256 + b) 1 bs.\n\n\
         {operators}\n\
         op kat_keccak (x : int list) : int list = let k = kat_key x in {root}.\n\n\
         clone Spec as KAT with\n  op keccak256 <- kat_keccak,\n{}.\nimport KAT.\n",
        bindings.join(",\n")
    );
    for (number, case) in group.cases.iter().enumerate() {
        let mut left = format!("KAT.{}", case.operator);
        for argument in &case.arguments {
            let _ = write!(left, " {}", ec(argument));
        }
        let _ = writeln!(
            text,
            "lemma kat_{number} :\n  {left}\n  = {}.\nproof. by cbv delta. qed.\n",
            ec(&case.result)
        );
    }
    let cases: Vec<Json> = group
        .cases
        .iter()
        .map(|case| {
            json!({
                "operator": case.operator,
                "arguments": case.arguments.iter().map(js).collect::<Vec<_>>(),
                "result": js(&case.result),
            })
        })
        .collect();
    let parameters: Map<String, Json> = group
        .parameters
        .iter()
        .map(|(name, value)| ((*name).to_string(), js(value)))
        .collect();
    let vectors = json!({ "group": group.name, "parameters": parameters, "cases": cases });
    let write = |dir: &str, file: String, body: String| -> Result<(), String> {
        let dir = out.join(dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        std::fs::write(dir.join(file), body).map_err(|e| e.to_string())
    };
    write("ec", format!("Kat_{}.ec", group.name), text)?;
    let body = serde_json::to_string_pretty(&vectors).map_err(|e| e.to_string())?;
    write("vectors", format!("{}.json", group.name), body + "\n")
}

#[cfg(test)]
mod tests {
    use super::key;

    #[test]
    fn key_is_the_base_256_integer_with_a_leading_one() {
        assert_eq!(key(&[]), "1");
        assert_eq!(key(&[0]), "256");
        assert_eq!(key(&[1, 2]), "65794");
        // 2^64 + 2^56 * 255 + ... : checked against Python int.from_bytes.
        assert_eq!(key(&[0xff; 8]), "36893488147419103231");
    }
}
