//! Deterministic, dependency-free generator for the canonical Deepwyrm ABI.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::fs;
use std::path::{Path, PathBuf};

mod render;
mod schema;
mod validation;

use render::*;
use schema::*;
use validation::*;

const SCHEMA_FILES: &[(&str, &[&str])] = &[
    ("abi.toml", &["newtype"]),
    ("status.toml", &["status"]),
    ("rights.toml", &["right"]),
    ("objects.toml", &["object", "signal"]),
    ("object_rights.toml", &["object_rights"]),
    (
        "boot.toml",
        &[
            "constant",
            "boot_info_flag",
            "memory_kind",
            "module_kind",
            "module_flag",
            "pixel_format",
            "framebuffer_flag",
            "entropy_source",
            "entropy_flag",
            "record",
        ],
    ),
    (
        "syscalls.toml",
        &["constant", "record", "object_info", "syscall"],
    ),
];

const OUTPUT_FILES: &[&str] = &[
    "deepwyrm_abi.rs",
    "deepwyrm_abi.h",
    "syscall_dispatch.rs",
    "syscall_kernel.rs",
    "syscall_wrappers.rs",
    "syscall_veneer_x86_64.S",
    "ABI.md",
    "README.md",
];

#[derive(Debug)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
enum Scalar {
    Text(String),
    Integer(i128),
}

#[derive(Clone, Debug)]
struct Table {
    path: PathBuf,
    line: usize,
    values: BTreeMap<String, Scalar>,
}

impl Table {
    fn label(&self) -> String {
        format!("{}:{}", self.path.display(), self.line)
    }

    fn text(&self, key: &str) -> Result<String> {
        match self.values.get(key) {
            Some(Scalar::Text(value)) => Ok(value.clone()),
            Some(_) => Err(Error::new(format!(
                "{}: key `{key}` must be a quoted string",
                self.label()
            ))),
            None => Err(Error::new(format!(
                "{}: missing required key `{key}`",
                self.label()
            ))),
        }
    }

    fn integer(&self, key: &str) -> Result<i128> {
        match self.values.get(key) {
            Some(Scalar::Integer(value)) => Ok(*value),
            Some(_) => Err(Error::new(format!(
                "{}: key `{key}` must be an integer",
                self.label()
            ))),
            None => Err(Error::new(format!(
                "{}: missing required key `{key}`",
                self.label()
            ))),
        }
    }

    fn reject_unknown(&self, allowed: &[&str], indexed_prefix: Option<&str>) -> Result<()> {
        for key in self.values.keys() {
            let indexed = indexed_prefix
                .and_then(|prefix| key.strip_prefix(prefix))
                .is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
                });
            if !allowed.contains(&key.as_str()) && !indexed {
                return Err(Error::new(format!(
                    "{}: unsupported key `{key}`",
                    self.label()
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Document {
    top: Table,
    arrays: BTreeMap<String, Vec<Table>>,
}

#[derive(Clone, Debug)]
struct Abi {
    name: String,
    version: u32,
    byte_order: String,
    pointer_width: u32,
    instruction: String,
    number_register: String,
    argument_registers: Vec<String>,
    result_register: String,
    clobbers: String,
    result_rule: String,
    rights_input_rule: String,
}

#[derive(Clone, Debug)]
struct Newtype {
    name: String,
    base: String,
    doc: String,
}

#[derive(Clone, Debug)]
struct ValueDef {
    name: String,
    value: i128,
    doc: String,
    extra: String,
}

#[derive(Clone, Debug)]
struct ValueSet {
    section: String,
    rust_type: String,
    prefix: String,
    values: Vec<ValueDef>,
}

#[derive(Clone, Debug)]
struct Constant {
    name: String,
    ty: String,
    value: i128,
    doc: String,
}

#[derive(Clone, Debug)]
enum FieldType {
    Named(String),
    Array(String, usize),
}

impl FieldType {
    fn rust(&self) -> String {
        match self {
            Self::Named(name) => name.clone(),
            Self::Array(name, count) => format!("[{name}; {count}]"),
        }
    }
}

#[derive(Clone, Debug)]
struct Field {
    name: String,
    ty: FieldType,
    doc: String,
}

#[derive(Clone, Debug)]
struct Record {
    name: String,
    doc: String,
    fields: Vec<Field>,
    size: usize,
    align: usize,
    offsets: Vec<usize>,
}

#[derive(Clone, Debug)]
struct Argument {
    name: String,
    ty: String,
    direction: String,
    object_type: String,
    rights: Vec<String>,
}

#[derive(Clone, Debug)]
struct Syscall {
    name: String,
    number: u32,
    phase: String,
    doc: String,
    arguments: Vec<Argument>,
}

#[derive(Clone, Debug)]
struct ObjectRights {
    object: String,
    object_value: u32,
    rights: Vec<String>,
    mask: u64,
}

#[derive(Clone, Debug)]
struct ObjectInfoTopic {
    topic: String,
    accepted_objects: String,
    result: String,
    incompatible_status: String,
    doc: String,
}

#[derive(Clone, Debug)]
struct Model {
    abi: Abi,
    newtypes: Vec<Newtype>,
    value_sets: Vec<ValueSet>,
    constants: Vec<Constant>,
    records: Vec<Record>,
    object_rights: Vec<ObjectRights>,
    known_rights_mask: u64,
    object_info_topics: Vec<ObjectInfoTopic>,
    syscalls: Vec<Syscall>,
}

impl Model {
    fn load(root: &Path) -> Result<Self> {
        let schema_dir = root.join("abi/schema");
        reject_unexpected_schema_files(&schema_dir)?;
        let mut documents = BTreeMap::new();
        for (name, sections) in SCHEMA_FILES {
            documents.insert(*name, parse_document(&schema_dir.join(name), sections)?);
        }

        let abi_doc = &documents["abi.toml"];
        abi_doc.top.reject_unknown(
            &[
                "schema_version",
                "abi_name",
                "abi_version",
                "byte_order",
                "pointer_width",
                "syscall_instruction",
                "syscall_number_register",
                "syscall_argument_registers",
                "syscall_result_register",
                "syscall_clobbers",
                "syscall_result_rule",
                "rights_input_rule",
            ],
            None,
        )?;
        require_schema_version(&abi_doc.top)?;
        let abi = Abi {
            name: abi_doc.top.text("abi_name")?,
            version: as_u32(&abi_doc.top, "abi_version")?,
            byte_order: abi_doc.top.text("byte_order")?,
            pointer_width: as_u32(&abi_doc.top, "pointer_width")?,
            instruction: abi_doc.top.text("syscall_instruction")?,
            number_register: abi_doc.top.text("syscall_number_register")?,
            argument_registers: abi_doc
                .top
                .text("syscall_argument_registers")?
                .split(',')
                .map(str::to_owned)
                .collect(),
            result_register: abi_doc.top.text("syscall_result_register")?,
            clobbers: abi_doc.top.text("syscall_clobbers")?,
            result_rule: abi_doc.top.text("syscall_result_rule")?,
            rights_input_rule: abi_doc.top.text("rights_input_rule")?,
        };
        if abi.byte_order != "little"
            || abi.pointer_width != 64
            || abi.instruction != "SYSCALL"
            || abi.number_register != "RAX"
            || abi.argument_registers != ["RDI", "RSI", "RDX", "R10", "R8", "R9"]
            || abi.result_register != "RAX"
            || abi.clobbers != "RCX,R11"
            || abi.result_rule != "DwStatus sign-extended to 64 bits"
        {
            return Err(Error::new(format!(
                "{}: unsupported raw x86_64 syscall convention",
                abi_doc.top.label()
            )));
        }

        let mut newtypes = Vec::new();
        let mut type_names = primitive_types();
        for table in tables(abi_doc, "newtype") {
            table.reject_unknown(&["name", "base", "doc"], None)?;
            let item = Newtype {
                name: table.text("name")?,
                base: table.text("base")?,
                doc: table.text("doc")?,
            };
            require_camel_type(&item.name, table)?;
            if !primitive_types().contains(&item.base) {
                return Err(Error::new(format!(
                    "{}: newtype base `{}` is not fixed-width",
                    table.label(),
                    item.base
                )));
            }
            if !type_names.insert(item.name.clone()) {
                return Err(Error::new(format!(
                    "{}: duplicate type name `{}`",
                    table.label(),
                    item.name
                )));
            }
            newtypes.push(item);
        }

        let mut value_sets = vec![
            load_value_set(
                &documents["status.toml"],
                "status",
                "DwStatus",
                "DW_STATUS",
                None,
            )?,
            load_value_set(
                &documents["rights.toml"],
                "right",
                "DwRights",
                "DW_RIGHT",
                None,
            )?,
            load_value_set(
                &documents["objects.toml"],
                "object",
                "DwObjectType",
                "DW_OBJECT_TYPE",
                Some("phase"),
            )?,
            load_value_set(
                &documents["objects.toml"],
                "signal",
                "DwSignals",
                "DW_SIGNAL",
                Some("applies_to"),
            )?,
        ];
        let boot_doc = &documents["boot.toml"];
        let boot_specs = [
            ("boot_info_flag", "DwBootInfoFlags", "DW_BOOT_INFO_FLAG"),
            ("memory_kind", "DwBootMemoryKind", "DW_BOOT_MEMORY_KIND"),
            ("module_kind", "DwBootModuleKind", "DW_BOOT_MODULE_KIND"),
            ("module_flag", "DwBootModuleFlags", "DW_BOOT_MODULE_FLAG"),
            ("pixel_format", "DwBootPixelFormat", "DW_BOOT_PIXEL_FORMAT"),
            (
                "framebuffer_flag",
                "DwBootFramebufferFlags",
                "DW_BOOT_FRAMEBUFFER_FLAG",
            ),
            (
                "entropy_source",
                "DwBootEntropySource",
                "DW_BOOT_ENTROPY_SOURCE",
            ),
            ("entropy_flag", "DwBootEntropyFlags", "DW_BOOT_ENTROPY_FLAG"),
        ];
        for (section, rust_type, prefix) in boot_specs {
            value_sets.push(load_value_set(boot_doc, section, rust_type, prefix, None)?);
        }

        validate_value_sets(&value_sets)?;
        let syscall_doc = &documents["syscalls.toml"];
        let mut constants = Vec::new();
        let bases = newtype_bases(&newtypes);
        for document in [boot_doc, syscall_doc] {
            for table in tables(document, "constant") {
                table.reject_unknown(&["name", "type", "value", "doc"], None)?;
                let constant = Constant {
                    name: table.text("name")?,
                    ty: table.text("type")?,
                    value: table.integer("value")?,
                    doc: table.text("doc")?,
                };
                require_upper_name(&constant.name, table)?;
                validate_scalar_value(&constant.ty, constant.value, &bases, table)?;
                constants.push(constant);
            }
        }
        reject_duplicate_names(constants.iter().map(|item| item.name.as_str()), "constant")?;

        let mut records = Vec::new();
        let mut layouts = type_layouts(&newtypes);
        for document in [boot_doc, syscall_doc] {
            for table in tables(document, "record") {
                let record = load_record(table, &layouts)?;
                if type_names.contains(&record.name) {
                    return Err(Error::new(format!(
                        "{}: duplicate type name `{}`",
                        table.label(),
                        record.name
                    )));
                }
                layouts.insert(record.name.clone(), (record.size, record.align));
                type_names.insert(record.name.clone());
                records.push(record);
            }
        }
        validate_boot_contract_constants(boot_doc, &constants)?;

        let object_set = value_sets
            .iter()
            .find(|set| set.section == "object")
            .unwrap();
        let right_set = value_sets
            .iter()
            .find(|set| set.section == "right")
            .unwrap();
        let object_names = object_set
            .values
            .iter()
            .map(|value| value.name.clone())
            .collect::<BTreeSet<_>>();
        let right_names = right_set
            .values
            .iter()
            .map(|value| value.name.clone())
            .collect::<BTreeSet<_>>();
        let (object_rights, known_rights_mask) =
            load_object_rights(&documents["object_rights.toml"], object_set, right_set)?;
        let status_names = value_sets
            .iter()
            .find(|set| set.section == "status")
            .unwrap()
            .values
            .iter()
            .map(|value| value.name.clone())
            .collect::<BTreeSet<_>>();
        let constant_names = constants
            .iter()
            .map(|constant| constant.name.clone())
            .collect::<BTreeSet<_>>();
        let mut object_info_topics = Vec::new();
        let mut object_info_topic_names = BTreeSet::new();
        for table in tables(syscall_doc, "object_info") {
            table.reject_unknown(
                &[
                    "topic",
                    "accepted_objects",
                    "result",
                    "incompatible_status",
                    "doc",
                ],
                None,
            )?;
            let topic = table.text("topic")?;
            if !constant_names.contains(&topic) {
                return Err(Error::new(format!(
                    "{}: object-info topic `{topic}` is not a declared constant",
                    table.label()
                )));
            }
            if !object_info_topic_names.insert(topic.clone()) {
                return Err(Error::new(format!(
                    "{}: duplicate object-info topic `{topic}`",
                    table.label()
                )));
            }
            let accepted_objects = table.text("accepted_objects")?;
            for object in accepted_objects.split(',') {
                if object != "ANY" && !object_names.contains(object) {
                    return Err(Error::new(format!(
                        "{}: object-info topic uses unknown object `{object}`",
                        table.label()
                    )));
                }
            }
            let result = table.text("result")?;
            if !type_names.contains(&result) {
                return Err(Error::new(format!(
                    "{}: object-info topic uses unknown result type `{result}`",
                    table.label()
                )));
            }
            let incompatible_status = table.text("incompatible_status")?;
            if !status_names.contains(&incompatible_status) {
                return Err(Error::new(format!(
                    "{}: object-info topic uses unknown status `{incompatible_status}`",
                    table.label()
                )));
            }
            object_info_topics.push(ObjectInfoTopic {
                topic,
                accepted_objects,
                result,
                incompatible_status,
                doc: table.text("doc")?,
            });
        }
        let mut syscalls = Vec::new();
        let mut syscall_ids = BTreeSet::new();
        let mut syscall_names = BTreeSet::new();
        for table in tables(syscall_doc, "syscall") {
            table.reject_unknown(&["name", "number", "phase", "doc"], Some("arg"))?;
            let name = table.text("name")?;
            require_snake_name(&name, table)?;
            let number = as_u32(table, "number")?;
            if number == 0 {
                return Err(Error::new(format!(
                    "{}: syscall ID zero is reserved",
                    table.label()
                )));
            }
            if number >= 0xffff_0000 {
                return Err(Error::new(format!(
                    "{}: debug/test syscall range is forbidden in the production ABI schema",
                    table.label()
                )));
            }
            if !syscall_ids.insert(number) {
                return Err(Error::new(format!(
                    "{}: duplicate syscall ID 0x{number:08x}",
                    table.label()
                )));
            }
            if !syscall_names.insert(name.clone()) {
                return Err(Error::new(format!(
                    "{}: duplicate syscall name `{name}`",
                    table.label()
                )));
            }
            let arguments = load_arguments(table, &type_names, &object_names, &right_names)?;
            if arguments.len() > abi.argument_registers.len() {
                return Err(Error::new(format!(
                    "{}: syscall `{name}` has {} arguments; maximum is {}",
                    table.label(),
                    arguments.len(),
                    abi.argument_registers.len()
                )));
            }
            let phase = table.text("phase")?;
            if !matches!(
                phase.as_str(),
                "DW0-A" | "DW0-B" | "DW0-C" | "DW0-D" | "DW0-E" | "DW0-F" | "DW0-G" | "DW0-H"
            ) {
                return Err(Error::new(format!(
                    "{}: syscall `{name}` uses unsupported implementation phase `{phase}`",
                    table.label()
                )));
            }
            syscalls.push(Syscall {
                name,
                number,
                phase,
                doc: table.text("doc")?,
                arguments,
            });
        }
        syscalls.sort_by_key(|syscall| syscall.number);
        validate_syscall_object_rights(&syscalls, &object_rights)?;

        Ok(Self {
            abi,
            newtypes,
            value_sets,
            constants,
            records,
            object_rights,
            known_rights_mask,
            object_info_topics,
            syscalls,
        })
    }
}

fn write_outputs_atomically(root: &Path, outputs: &BTreeMap<String, String>) -> Result<()> {
    let abi_dir = root.join("abi");
    let destination = abi_dir.join("generated");
    let pid = std::process::id();
    let staging = abi_dir.join(format!(".generated.tmp.{pid}"));
    let backup = abi_dir.join(format!(".generated.old.{pid}"));
    if staging.exists() || backup.exists() {
        return Err(Error::new(format!(
            "{}: stale abi-gen staging path exists",
            abi_dir.display()
        )));
    }
    fs::create_dir(&staging)
        .map_err(|error| Error::new(format!("{}: {error}", staging.display())))?;
    let staged = (|| {
        for (name, contents) in outputs {
            fs::write(staging.join(name), contents).map_err(|error| {
                Error::new(format!("{}: {error}", staging.join(name).display()))
            })?;
        }
        if destination.exists() {
            fs::rename(&destination, &backup).map_err(|error| {
                Error::new(format!(
                    "{} -> {}: {error}",
                    destination.display(),
                    backup.display()
                ))
            })?;
        }
        match fs::rename(&staging, &destination) {
            Ok(()) => {
                if backup.exists() {
                    fs::remove_dir_all(&backup)
                        .map_err(|error| Error::new(format!("{}: {error}", backup.display())))?;
                }
                Ok(())
            }
            Err(error) => {
                if backup.exists() && !destination.exists() {
                    let _ = fs::rename(&backup, &destination);
                }
                Err(Error::new(format!(
                    "{} -> {}: {error}",
                    staging.display(),
                    destination.display()
                )))
            }
        }
    })();
    if staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    staged
}

fn check_outputs(root: &Path, outputs: &BTreeMap<String, String>) -> Result<()> {
    let directory = root.join("abi/generated");
    let mut drift = Vec::new();
    for (name, expected) in outputs {
        let path = directory.join(name);
        match fs::read_to_string(&path) {
            Ok(actual) if actual == *expected => {}
            Ok(_) => drift.push(format!("{}: generated content is stale", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                drift.push(format!("{}: generated file is missing", path.display()))
            }
            Err(error) => drift.push(format!("{}: {error}", path.display())),
        }
    }
    if let Ok(entries) = fs::read_dir(&directory) {
        let expected = OUTPUT_FILES.iter().copied().collect::<BTreeSet<_>>();
        for entry in entries {
            let entry =
                entry.map_err(|error| Error::new(format!("{}: {error}", directory.display())))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !expected.contains(name.as_ref()) {
                drift.push(format!(
                    "{}: unexpected generated artifact",
                    entry.path().display()
                ));
            }
        }
    }
    if drift.is_empty() {
        Ok(())
    } else {
        Err(Error::new(format!(
            "generated ABI drift detected:\n{}\nrun `abi-gen generate` from the repository root",
            drift.join("\n")
        )))
    }
}

fn resolve_root(explicit: Option<PathBuf>) -> Result<PathBuf> {
    let root = match explicit {
        Some(root) => root,
        None => std::env::current_dir().map_err(|error| Error::new(error.to_string()))?,
    };
    if !root.join("abi/schema/abi.toml").is_file() {
        return Err(Error::new(format!(
            "{}: not a Deepwyrm repository root (missing abi/schema/abi.toml)",
            root.display()
        )));
    }
    Ok(root)
}

/// Execute the command-line interface using process-style arguments excluding `argv[0]`.
pub fn run<I, S>(arguments: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let command = arguments
        .next()
        .ok_or_else(|| Error::new("usage: abi-gen <generate|check> [--root <path>]"))?;
    let command = command
        .to_str()
        .ok_or_else(|| Error::new("command is not valid UTF-8"))?;
    let mut root = None;
    while let Some(argument) = arguments.next() {
        if argument != "--root" {
            return Err(Error::new(format!(
                "unsupported argument `{}`",
                argument.to_string_lossy()
            )));
        }
        if root.is_some() {
            return Err(Error::new("`--root` may be specified only once"));
        }
        root = Some(PathBuf::from(
            arguments
                .next()
                .ok_or_else(|| Error::new("`--root` requires a path"))?,
        ));
    }
    if !matches!(command, "generate" | "check") {
        return Err(Error::new(format!(
            "unknown command `{command}`; expected `generate` or `check`"
        )));
    }
    let root = resolve_root(root)?;
    let model = Model::load(&root)?;
    let outputs = render(&model)?;
    match command {
        "generate" => write_outputs_atomically(&root, &outputs),
        "check" => check_outputs(&root, &outputs),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests;
