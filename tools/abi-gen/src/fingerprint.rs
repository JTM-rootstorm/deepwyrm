//! Semantic ABI fingerprint.
//!
//! The fingerprint is a SHA-256 digest over a normalized encoding of the
//! validated [`Model`]. It covers everything a paired consumer compiles or
//! links against: the raw syscall convention, type names and bases, every
//! value set (statuses, rights, objects, signals and boot enumerations),
//! constants, record fields with their computed layouts, object/right and
//! object/signal relations, object-info topics, and each syscall's number,
//! arguments, directions, object types and rights.
//!
//! It deliberately excludes documentation text (every `doc` key and the
//! documentation part of record field descriptors) and the implementation
//! phase of syscalls and object types, which the generated dispatch already
//! labels as generator metadata rather than native ABI. Entries whose order
//! carries no meaning (value-set members, constants, records, relations and
//! right sets) are sorted, so moving a table within a schema file does not
//! change the fingerprint. Record fields, syscall arguments and the argument
//! register list keep their order because their order is the ABI.
//!
//! Every model structure is destructured without `..`, so adding a field to
//! the model fails to compile here until the field is classified.

use super::*;

/// Generated file carrying the fingerprint beside the other ABI artifacts.
pub(super) const FINGERPRINT_FILE: &str = "abi_fingerprint.toml";

/// Identity of the encoding below; bump it whenever the encoding changes.
pub(super) const FINGERPRINT_SCHEMA: &str = "deepwyrm-abi-fingerprint-v1";

/// Length-prefixed, line-oriented encoder. Keys are fixed identifiers and
/// every text value carries its byte length, so the encoding is unambiguous.
struct Canonical(String);

impl Canonical {
    fn text(&mut self, key: &str, value: &str) {
        writeln!(self.0, "{key} {}:{value}", value.len()).unwrap();
    }

    fn integer(&mut self, key: &str, value: i128) {
        writeln!(self.0, "{key} {value}").unwrap();
    }

    fn count(&mut self, key: &str, value: usize) {
        writeln!(self.0, "{key} #{value}").unwrap();
    }

    fn set<'a>(&mut self, key: &str, values: impl IntoIterator<Item = &'a str>) {
        let mut values = values.into_iter().collect::<Vec<_>>();
        values.sort_unstable();
        self.count(key, values.len());
        for value in values {
            self.text("member", value);
        }
    }
}

/// Render the normalized, documentation-free encoding that is hashed.
pub(super) fn canonical_form(model: &Model) -> String {
    let Model {
        abi,
        newtypes,
        value_sets,
        constants,
        records,
        object_rights,
        known_rights_mask,
        object_signals,
        known_signals_mask,
        object_info_topics,
        syscalls,
    } = model;
    let mut out = Canonical(String::new());
    out.text("encoding", FINGERPRINT_SCHEMA);

    let Abi {
        name,
        version,
        byte_order,
        pointer_width,
        instruction,
        number_register,
        argument_registers,
        result_register,
        clobbers,
        result_rule,
        rights_input_rule,
    } = abi;
    out.text("abi_name", name);
    out.integer("abi_version", i128::from(*version));
    out.text("byte_order", byte_order);
    out.integer("pointer_width", i128::from(*pointer_width));
    out.text("syscall_instruction", instruction);
    out.text("syscall_number_register", number_register);
    out.count("syscall_argument_registers", argument_registers.len());
    for register in argument_registers {
        out.text("register", register);
    }
    out.text("syscall_result_register", result_register);
    out.text("syscall_clobbers", clobbers);
    out.text("syscall_result_rule", result_rule);
    out.text("rights_input_rule", rights_input_rule);

    let mut newtypes = newtypes.iter().collect::<Vec<_>>();
    newtypes.sort_by(|left, right| left.name.cmp(&right.name));
    out.count("newtypes", newtypes.len());
    for Newtype { name, base, doc: _ } in newtypes {
        out.text("newtype", name);
        out.text("base", base);
    }

    let mut value_sets = value_sets.iter().collect::<Vec<_>>();
    value_sets.sort_by(|left, right| left.section.cmp(&right.section));
    out.count("value_sets", value_sets.len());
    for ValueSet {
        section,
        rust_type,
        prefix,
        values,
    } in value_sets
    {
        out.text("value_set", section);
        out.text("rust_type", rust_type);
        out.text("prefix", prefix);
        // Object types carry their implementation phase as the extra key;
        // signals carry `applies_to`, which is part of the ABI.
        let extra_is_abi = section != "object";
        let mut values = values.iter().collect::<Vec<_>>();
        values.sort_by(|left, right| left.name.cmp(&right.name));
        out.count("values", values.len());
        for ValueDef {
            name,
            value,
            doc: _,
            extra,
        } in values
        {
            out.text("value", name);
            out.integer("number", *value);
            if extra_is_abi {
                out.text("extra", extra);
            }
        }
    }

    let mut constants = constants.iter().collect::<Vec<_>>();
    constants.sort_by(|left, right| left.name.cmp(&right.name));
    out.count("constants", constants.len());
    for Constant {
        name,
        ty,
        value,
        doc: _,
    } in constants
    {
        out.text("constant", name);
        out.text("type", ty);
        out.integer("value", *value);
    }

    let mut records = records.iter().collect::<Vec<_>>();
    records.sort_by(|left, right| left.name.cmp(&right.name));
    out.count("records", records.len());
    for Record {
        name,
        doc: _,
        fields,
        size,
        align,
        offsets,
    } in records
    {
        out.text("record", name);
        out.count("size", *size);
        out.count("align", *align);
        out.count("fields", fields.len());
        for (Field { name, ty, doc: _ }, offset) in fields.iter().zip(offsets) {
            out.text("field", name);
            match ty {
                FieldType::Named(type_name) => out.text("named", type_name),
                FieldType::Array(type_name, count) => {
                    out.text("array", type_name);
                    out.count("length", *count);
                }
            }
            out.count("offset", *offset);
        }
    }

    let mut object_rights = object_rights.iter().collect::<Vec<_>>();
    object_rights.sort_by(|left, right| left.object.cmp(&right.object));
    out.count("object_rights", object_rights.len());
    for ObjectRights {
        object,
        object_value,
        rights,
        mask,
    } in object_rights
    {
        out.text("object", object);
        out.integer("object_value", i128::from(*object_value));
        out.set("rights", rights.iter().map(String::as_str));
        out.integer("mask", i128::from(*mask));
    }
    out.integer("known_rights_mask", i128::from(*known_rights_mask));

    let mut object_signals = object_signals.iter().collect::<Vec<_>>();
    object_signals.sort_by(|left, right| left.object.cmp(&right.object));
    out.count("object_signals", object_signals.len());
    for ObjectSignals {
        object,
        object_value,
        signals,
        mask,
    } in object_signals
    {
        out.text("object", object);
        out.integer("object_value", i128::from(*object_value));
        out.set("signals", signals.iter().map(String::as_str));
        out.integer("mask", i128::from(*mask));
    }
    out.integer("known_signals_mask", i128::from(*known_signals_mask));

    let mut object_info_topics = object_info_topics.iter().collect::<Vec<_>>();
    object_info_topics.sort_by(|left, right| left.topic.cmp(&right.topic));
    out.count("object_info_topics", object_info_topics.len());
    for ObjectInfoTopic {
        topic,
        accepted_objects,
        result,
        incompatible_status,
        doc: _,
    } in object_info_topics
    {
        out.text("topic", topic);
        out.set("accepted_objects", accepted_objects.split(','));
        out.text("result", result);
        out.text("incompatible_status", incompatible_status);
    }

    let mut syscalls = syscalls.iter().collect::<Vec<_>>();
    syscalls.sort_by_key(|syscall| syscall.number);
    out.count("syscalls", syscalls.len());
    for Syscall {
        name,
        number,
        phase: _,
        doc: _,
        arguments,
    } in syscalls
    {
        out.text("syscall", name);
        out.integer("number", i128::from(*number));
        out.count("arguments", arguments.len());
        for Argument {
            name,
            ty,
            direction,
            object_type,
            rights,
        } in arguments
        {
            out.text("argument", name);
            out.text("type", ty);
            out.text("direction", direction);
            out.text("object_type", object_type);
            out.set("rights", rights.iter().map(String::as_str));
        }
    }
    out.0
}

/// Lowercase hexadecimal SHA-256 of the canonical form.
pub(super) fn fingerprint(model: &Model) -> String {
    hex(&sha256(canonical_form(model).as_bytes()))
}

pub(super) fn render_fingerprint(model: &Model) -> String {
    let mut out = generated_preamble("#");
    out.push_str(
        "# Semantic ABI fingerprint: SHA-256 over the normalized schema with\n\
         # documentation text and implementation-phase metadata excluded. A\n\
         # paired consumer compares this value, not the abi/ tree, so a\n\
         # documentation-only schema edit does not change it.\n\n",
    );
    writeln!(out, "schema = \"{FINGERPRINT_SCHEMA}\"").unwrap();
    writeln!(out, "abi_name = \"{}\"", model.abi.name).unwrap();
    writeln!(out, "abi_version = {}", model.abi.version).unwrap();
    writeln!(out, "algorithm = \"sha256\"").unwrap();
    writeln!(out, "fingerprint = \"{}\"", fingerprint(model)).unwrap();
    out
}

pub(super) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").unwrap();
    }
    out
}

const SHA256_INITIAL: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA256_ROUND: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Dependency-free SHA-256 (FIPS 180-4), sufficient for hashing the
/// canonical form; it is not used for any secret material.
pub(super) fn sha256(message: &[u8]) -> [u8; 32] {
    let mut state = SHA256_INITIAL;
    let bit_length = (message.len() as u64).wrapping_mul(8);
    let mut padded = message.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    for block in padded.as_chunks::<64>().0 {
        let mut schedule = [0u32; 64];
        for (word, bytes) in schedule.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for (constant, word) in SHA256_ROUND.iter().zip(schedule) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ (!e & g);
            let first = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(*constant)
                .wrapping_add(word);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut digest = [0u8; 32];
    for (bytes, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *bytes = word.to_be_bytes();
    }
    digest
}
