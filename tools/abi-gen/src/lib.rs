//! Deterministic, dependency-free generator for the canonical Deepwyrm ABI.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::fs;
use std::path::{Path, PathBuf};

const SCHEMA_FILES: &[(&str, &[&str])] = &[
    ("abi.toml", &["newtype"]),
    ("status.toml", &["status"]),
    ("rights.toml", &["right"]),
    ("objects.toml", &["object", "signal"]),
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
    "syscall_wrappers.rs",
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

fn parse_document(path: &Path, allowed_sections: &[&str]) -> Result<Document> {
    let input = fs::read_to_string(path)
        .map_err(|error| Error::new(format!("{}: {error}", path.display())))?;
    let mut top = Table {
        path: path.to_path_buf(),
        line: 1,
        values: BTreeMap::new(),
    };
    let mut arrays: BTreeMap<String, Vec<Table>> = BTreeMap::new();
    let mut current: Option<(String, usize)> = None;

    for (index, raw) in input.lines().enumerate() {
        let line = index + 1;
        let text = raw.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        if text.starts_with("[[") {
            if !text.ends_with("]]") || text.len() < 5 {
                return Err(Error::new(format!(
                    "{}:{line}: malformed array-table header",
                    path.display()
                )));
            }
            let name = &text[2..text.len() - 2];
            if !allowed_sections.contains(&name) {
                return Err(Error::new(format!(
                    "{}:{line}: unsupported section `[[{name}]]`",
                    path.display()
                )));
            }
            arrays.entry(name.to_owned()).or_default().push(Table {
                path: path.to_path_buf(),
                line,
                values: BTreeMap::new(),
            });
            current = Some((name.to_owned(), arrays[name].len() - 1));
            continue;
        }
        if text.starts_with('[') {
            return Err(Error::new(format!(
                "{}:{line}: ordinary TOML tables are unsupported",
                path.display()
            )));
        }
        let (key, raw_value) = text.split_once('=').ok_or_else(|| {
            Error::new(format!("{}:{line}: expected `key = value`", path.display()))
        })?;
        let key = key.trim();
        if !valid_key(key) {
            return Err(Error::new(format!(
                "{}:{line}: invalid key `{key}`",
                path.display()
            )));
        }
        let value = parse_scalar(path, line, raw_value.trim())?;
        let target = match &current {
            Some((section, table_index)) => &mut arrays.get_mut(section).unwrap()[*table_index],
            None => &mut top,
        };
        if target.values.insert(key.to_owned(), value).is_some() {
            return Err(Error::new(format!(
                "{}:{line}: duplicate key `{key}` in the same table",
                path.display()
            )));
        }
    }
    Ok(Document { top, arrays })
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn parse_scalar(path: &Path, line: usize, value: &str) -> Result<Scalar> {
    if value.starts_with('"') {
        if value.len() < 2 || !value.ends_with('"') {
            return Err(Error::new(format!(
                "{}:{line}: unterminated quoted string",
                path.display()
            )));
        }
        let inner = &value[1..value.len() - 1];
        if inner.contains('"') || inner.contains('\\') {
            return Err(Error::new(format!(
                "{}:{line}: string escapes and embedded quotes are unsupported",
                path.display()
            )));
        }
        return Ok(Scalar::Text(inner.to_owned()));
    }
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        i128::from_str_radix(hex, 16)
    } else if let Some(hex) = value.strip_prefix("-0x") {
        i128::from_str_radix(hex, 16).map(|number| -number)
    } else {
        value.parse::<i128>()
    };
    parsed.map(Scalar::Integer).map_err(|_| {
        Error::new(format!(
            "{}:{line}: unsupported or malformed value `{value}`",
            path.display()
        ))
    })
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
            || abi.argument_registers.len() != 6
        {
            return Err(Error::new(format!(
                "{}: unsupported ABI machine contract",
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

        let object_names = value_sets
            .iter()
            .find(|set| set.section == "object")
            .unwrap()
            .values
            .iter()
            .map(|value| value.name.clone())
            .collect::<BTreeSet<_>>();
        let right_names = value_sets
            .iter()
            .find(|set| set.section == "right")
            .unwrap()
            .values
            .iter()
            .map(|value| value.name.clone())
            .collect::<BTreeSet<_>>();
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
            syscalls.push(Syscall {
                name,
                number,
                phase: table.text("phase")?,
                doc: table.text("doc")?,
                arguments,
            });
        }
        syscalls.sort_by_key(|syscall| syscall.number);

        Ok(Self {
            abi,
            newtypes,
            value_sets,
            constants,
            records,
            object_info_topics,
            syscalls,
        })
    }
}

fn validate_boot_contract_constants(boot_doc: &Document, constants: &[Constant]) -> Result<()> {
    for table in tables(boot_doc, "record") {
        let record_name = table.text("name")?;
        let Some(stem) = record_name
            .strip_prefix("Dw")
            .and_then(|name| name.strip_suffix("V1"))
        else {
            continue;
        };
        let expected = format!("DW_{}_V1_VERSION", camel_to_upper_snake(stem));
        require_u32_constant(constants, &expected, 1)?;
    }
    require_u32_constant(constants, "DW_BOOT_BASE_PAGE_SIZE", 4096)
}

fn require_u32_constant(constants: &[Constant], name: &str, value: i128) -> Result<()> {
    match constants.iter().find(|constant| constant.name == name) {
        Some(constant) if constant.ty == "u32" && constant.value == value => Ok(()),
        Some(_) => Err(Error::new(format!(
            "boot contract constant `{name}` must have type u32 and value {value}"
        ))),
        None => Err(Error::new(format!(
            "boot contract requires constant `{name}` with type u32 and value {value}"
        ))),
    }
}

fn reject_unexpected_schema_files(directory: &Path) -> Result<()> {
    let expected = SCHEMA_FILES
        .iter()
        .map(|(name, _)| *name)
        .collect::<BTreeSet<_>>();
    for entry in fs::read_dir(directory)
        .map_err(|error| Error::new(format!("{}: {error}", directory.display())))?
    {
        let entry =
            entry.map_err(|error| Error::new(format!("{}: {error}", directory.display())))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".toml") && !expected.contains(name.as_ref()) {
            return Err(Error::new(format!(
                "{}: unsupported schema file `{name}`",
                directory.display()
            )));
        }
    }
    Ok(())
}

fn require_schema_version(table: &Table) -> Result<()> {
    if table.integer("schema_version")? != 1 {
        return Err(Error::new(format!(
            "{}: unsupported schema_version; expected 1",
            table.label()
        )));
    }
    Ok(())
}

fn tables<'a>(document: &'a Document, section: &str) -> &'a [Table] {
    document
        .arrays
        .get(section)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn as_u32(table: &Table, key: &str) -> Result<u32> {
    u32::try_from(table.integer(key)?).map_err(|_| {
        Error::new(format!(
            "{}: key `{key}` is outside the u32 range",
            table.label()
        ))
    })
}

fn load_value_set(
    document: &Document,
    section: &str,
    rust_type: &str,
    prefix: &str,
    extra_key: Option<&str>,
) -> Result<ValueSet> {
    document.top.reject_unknown(&["schema_version"], None)?;
    require_schema_version(&document.top)?;
    let mut allowed = vec!["name", "value", "doc"];
    if let Some(extra) = extra_key {
        allowed.push(extra);
    }
    let mut values = Vec::new();
    for table in tables(document, section) {
        table.reject_unknown(&allowed, None)?;
        let name = table.text("name")?;
        require_upper_name(&name, table)?;
        values.push(ValueDef {
            name,
            value: table.integer("value")?,
            doc: table.text("doc")?,
            extra: match extra_key {
                Some(key) => table.text(key)?,
                None => String::new(),
            },
        });
    }
    Ok(ValueSet {
        section: section.to_owned(),
        rust_type: rust_type.to_owned(),
        prefix: prefix.to_owned(),
        values,
    })
}

fn validate_value_sets(sets: &[ValueSet]) -> Result<()> {
    for set in sets {
        let mut names = BTreeSet::new();
        let mut values = BTreeSet::new();
        for item in &set.values {
            let in_range = match set.rust_type.as_str() {
                "DwStatus" => i32::try_from(item.value).is_ok(),
                "DwRights" | "DwSignals" | "DwBootInfoFlags" => u64::try_from(item.value).is_ok(),
                "DwObjectType"
                | "DwBootMemoryKind"
                | "DwBootModuleKind"
                | "DwBootModuleFlags"
                | "DwBootPixelFormat"
                | "DwBootFramebufferFlags"
                | "DwBootEntropySource"
                | "DwBootEntropyFlags" => u32::try_from(item.value).is_ok(),
                _ => false,
            };
            if !in_range {
                return Err(Error::new(format!(
                    "{} `{}` value {} does not fit `{}`",
                    set.section, item.name, item.value, set.rust_type
                )));
            }
            if !names.insert(item.name.clone()) {
                return Err(Error::new(format!(
                    "duplicate {} name `{}`",
                    set.section, item.name
                )));
            }
            if !values.insert(item.value) {
                return Err(Error::new(format!(
                    "duplicate {} value {}",
                    set.section, item.value
                )));
            }
            if matches!(
                set.section.as_str(),
                "right"
                    | "signal"
                    | "boot_info_flag"
                    | "module_flag"
                    | "framebuffer_flag"
                    | "entropy_flag"
            ) && (item.value <= 0 || (item.value & (item.value - 1)) != 0)
            {
                return Err(Error::new(format!(
                    "{} `{}` value must be one nonzero bit",
                    set.section, item.name
                )));
            }
            if set.section == "status"
                && ((item.name == "SUCCESS" && item.value != 0)
                    || (item.name != "SUCCESS" && item.value >= 0))
            {
                return Err(Error::new(format!(
                    "status `{}` violates zero-success/negative-failure policy",
                    item.name
                )));
            }
        }
    }
    let objects = sets.iter().find(|set| set.section == "object").unwrap();
    let zero = objects
        .values
        .iter()
        .filter(|item| item.value == 0)
        .collect::<Vec<_>>();
    if zero.len() != 1 || zero[0].name != "NONE" {
        return Err(Error::new(
            "object type zero must be assigned exactly once to NONE",
        ));
    }
    Ok(())
}

fn primitive_types() -> BTreeSet<String> {
    ["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn newtype_bases(newtypes: &[Newtype]) -> BTreeMap<String, String> {
    newtypes
        .iter()
        .map(|item| (item.name.clone(), item.base.clone()))
        .collect()
}

fn type_layouts(newtypes: &[Newtype]) -> BTreeMap<String, (usize, usize)> {
    let mut result = BTreeMap::new();
    for primitive in primitive_types() {
        let bytes = primitive[1..].parse::<usize>().unwrap() / 8;
        result.insert(primitive, (bytes, bytes));
    }
    for item in newtypes {
        let layout = result[&item.base];
        result.insert(item.name.clone(), layout);
    }
    result
}

fn validate_scalar_value(
    ty: &str,
    value: i128,
    bases: &BTreeMap<String, String>,
    table: &Table,
) -> Result<()> {
    let base = bases.get(ty).map(String::as_str).unwrap_or(ty);
    let valid = match base {
        "u8" => u8::try_from(value).is_ok(),
        "u16" => u16::try_from(value).is_ok(),
        "u32" => u32::try_from(value).is_ok(),
        "u64" => u64::try_from(value).is_ok(),
        "i8" => i8::try_from(value).is_ok(),
        "i16" => i16::try_from(value).is_ok(),
        "i32" => i32::try_from(value).is_ok(),
        "i64" => i64::try_from(value).is_ok(),
        _ => false,
    };
    if !valid {
        return Err(Error::new(format!(
            "{}: value {value} does not fit fixed-width type `{ty}`",
            table.label()
        )));
    }
    Ok(())
}

fn load_record(table: &Table, layouts: &BTreeMap<String, (usize, usize)>) -> Result<Record> {
    table.reject_unknown(&["name", "doc"], Some("field"))?;
    let name = table.text("name")?;
    require_camel_type(&name, table)?;
    let mut fields = Vec::new();
    for index in 0.. {
        let key = format!("field{index}");
        let Some(value) = table.values.get(&key) else {
            break;
        };
        let Scalar::Text(value) = value else {
            return Err(Error::new(format!(
                "{}: `{key}` must be a quoted field descriptor",
                table.label()
            )));
        };
        let parts = value.split('|').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Err(Error::new(format!(
                "{}: `{key}` must be `name|type|documentation`",
                table.label()
            )));
        }
        require_snake_name(parts[0], table)?;
        fields.push(Field {
            name: parts[0].to_owned(),
            ty: parse_field_type(parts[1], layouts, table)?,
            doc: parts[2].to_owned(),
        });
    }
    let indexed = table.values.keys().filter_map(|key| {
        key.strip_prefix("field")
            .and_then(|suffix| suffix.parse::<usize>().ok())
    });
    if indexed
        .max()
        .is_some_and(|maximum| maximum + 1 != fields.len())
    {
        return Err(Error::new(format!(
            "{}: record fields must use contiguous field0..fieldN keys",
            table.label()
        )));
    }
    if fields.is_empty() {
        return Err(Error::new(format!(
            "{}: record has no fields",
            table.label()
        )));
    }
    let mut names = BTreeSet::new();
    let mut offsets = Vec::new();
    let mut size = 0usize;
    let mut align = 1usize;
    for field in &fields {
        if !names.insert(field.name.clone()) {
            return Err(Error::new(format!(
                "{}: duplicate field `{}`",
                table.label(),
                field.name
            )));
        }
        let (field_size, field_align) = field_layout(&field.ty, layouts);
        size = align_up(size, field_align)?;
        offsets.push(size);
        size = size
            .checked_add(field_size)
            .ok_or_else(|| Error::new(format!("{}: record layout overflows", table.label())))?;
        align = align.max(field_align);
    }
    size = align_up(size, align)?;
    Ok(Record {
        name,
        doc: table.text("doc")?,
        fields,
        size,
        align,
        offsets,
    })
}

fn parse_field_type(
    text: &str,
    layouts: &BTreeMap<String, (usize, usize)>,
    table: &Table,
) -> Result<FieldType> {
    if let Some(inner) = text
        .strip_prefix('[')
        .and_then(|text| text.strip_suffix(']'))
    {
        let (name, count) = inner.split_once(';').ok_or_else(|| {
            Error::new(format!("{}: malformed array type `{text}`", table.label()))
        })?;
        let count = count.parse::<usize>().map_err(|_| {
            Error::new(format!(
                "{}: malformed array count `{count}`",
                table.label()
            ))
        })?;
        if count == 0 || count > 1024 || !layouts.contains_key(name) {
            return Err(Error::new(format!(
                "{}: unsupported array type `{text}`",
                table.label()
            )));
        }
        Ok(FieldType::Array(name.to_owned(), count))
    } else if layouts.contains_key(text) {
        Ok(FieldType::Named(text.to_owned()))
    } else {
        Err(Error::new(format!(
            "{}: unknown or forward-referenced field type `{text}`",
            table.label()
        )))
    }
}

fn field_layout(ty: &FieldType, layouts: &BTreeMap<String, (usize, usize)>) -> (usize, usize) {
    match ty {
        FieldType::Named(name) => layouts[name],
        FieldType::Array(name, count) => (layouts[name].0 * count, layouts[name].1),
    }
}

fn align_up(value: usize, align: usize) -> Result<usize> {
    value
        .checked_add(align - 1)
        .map(|value| value & !(align - 1))
        .ok_or_else(|| Error::new("record layout arithmetic overflow"))
}

fn load_arguments(
    table: &Table,
    types: &BTreeSet<String>,
    objects: &BTreeSet<String>,
    rights: &BTreeSet<String>,
) -> Result<Vec<Argument>> {
    let mut result = Vec::new();
    for index in 0.. {
        let key = format!("arg{index}");
        let Some(value) = table.values.get(&key) else {
            break;
        };
        let Scalar::Text(value) = value else {
            return Err(Error::new(format!(
                "{}: `{key}` must be quoted",
                table.label()
            )));
        };
        let parts = value.split('|').collect::<Vec<_>>();
        if parts.len() != 5 {
            return Err(Error::new(format!(
                "{}: `{key}` must be `name|type|direction|object|rights`",
                table.label()
            )));
        }
        require_snake_name(parts[0], table)?;
        if !types.contains(parts[1]) {
            return Err(Error::new(format!(
                "{}: syscall argument uses unknown type `{}`",
                table.label(),
                parts[1]
            )));
        }
        if !matches!(parts[2], "in" | "out" | "inout") {
            return Err(Error::new(format!(
                "{}: invalid argument direction `{}`",
                table.label(),
                parts[2]
            )));
        }
        if !matches!(parts[3], "NONE" | "ANY") && !objects.contains(parts[3]) {
            return Err(Error::new(format!(
                "{}: unknown required object type `{}`",
                table.label(),
                parts[3]
            )));
        }
        let required_rights = if parts[4] == "NONE" {
            Vec::new()
        } else {
            parts[4].split('+').map(str::to_owned).collect::<Vec<_>>()
        };
        for right in &required_rights {
            if !rights.contains(right) {
                return Err(Error::new(format!(
                    "{}: unknown required right `{right}`",
                    table.label()
                )));
            }
        }
        result.push(Argument {
            name: parts[0].to_owned(),
            ty: parts[1].to_owned(),
            direction: parts[2].to_owned(),
            object_type: parts[3].to_owned(),
            rights: required_rights,
        });
    }
    let maximum = table.values.keys().filter_map(|key| {
        key.strip_prefix("arg")
            .and_then(|suffix| suffix.parse::<usize>().ok())
    });
    if maximum
        .max()
        .is_some_and(|maximum| maximum + 1 != result.len())
    {
        return Err(Error::new(format!(
            "{}: syscall arguments must use contiguous arg0..argN keys",
            table.label()
        )));
    }
    Ok(result)
}

fn require_upper_name(name: &str, table: &Table) -> Result<()> {
    if name.is_empty()
        || !name.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
        })
    {
        return Err(Error::new(format!(
            "{}: `{name}` is not an uppercase ABI name",
            table.label()
        )));
    }
    Ok(())
}

fn require_snake_name(name: &str, table: &Table) -> Result<()> {
    if name.is_empty()
        || !name.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
    {
        return Err(Error::new(format!(
            "{}: `{name}` is not a lowercase ABI name",
            table.label()
        )));
    }
    Ok(())
}

fn require_camel_type(name: &str, table: &Table) -> Result<()> {
    let architecture_token_count = name.matches("X86_64").count();
    let normalized = name.replace("X86_64", "X8664");
    if !name.starts_with("Dw")
        || architecture_token_count > 1
        || !normalized
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        return Err(Error::new(format!(
            "{}: `{name}` is not a Deepwyrm ABI type name",
            table.label()
        )));
    }
    Ok(())
}

fn reject_duplicate_names<'a>(names: impl Iterator<Item = &'a str>, kind: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    for name in names {
        if !seen.insert(name) {
            return Err(Error::new(format!("duplicate {kind} name `{name}`")));
        }
    }
    Ok(())
}

fn render(model: &Model) -> Result<BTreeMap<String, String>> {
    let mut outputs = BTreeMap::new();
    outputs.insert("deepwyrm_abi.rs".to_owned(), render_rust(model)?);
    outputs.insert("deepwyrm_abi.h".to_owned(), render_c(model)?);
    outputs.insert(
        "syscall_dispatch.rs".to_owned(),
        render_dispatch_metadata(model)?,
    );
    outputs.insert(
        "syscall_wrappers.rs".to_owned(),
        render_wrapper_metadata(model)?,
    );
    outputs.insert("ABI.md".to_owned(), render_markdown(model)?);
    outputs.insert("README.md".to_owned(), render_readme());
    for contents in outputs.values_mut() {
        contents.truncate(contents.trim_end().len());
        contents.push('\n');
    }
    Ok(outputs)
}

fn generated_preamble(comment: &str) -> String {
    format!(
        "{comment} @generated by abi-gen from abi/schema.\n{comment} Do not edit this file directly.\n\n"
    )
}

fn render_rust(model: &Model) -> Result<String> {
    let mut out = generated_preamble("//");
    writeln!(out, "/// Native Deepwyrm ABI version.").unwrap();
    writeln!(
        out,
        "pub const DW_ABI_VERSION: u32 = {};\n",
        model.abi.version
    )
    .unwrap();

    for item in &model.newtypes {
        writeln!(out, "/// {}", item.doc).unwrap();
        writeln!(out, "#[repr(transparent)]").unwrap();
        writeln!(
            out,
            "#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]"
        )
        .unwrap();
        writeln!(out, "pub struct {}(pub {});\n", item.name, item.base).unwrap();
    }

    for set in &model.value_sets {
        for item in &set.values {
            writeln!(out, "/// {}", item.doc).unwrap();
            writeln!(
                out,
                "pub const {}_{}: {} = {}({});\n",
                set.prefix, item.name, set.rust_type, set.rust_type, item.value
            )
            .unwrap();
        }
    }
    for constant in &model.constants {
        writeln!(out, "/// {}", constant.doc).unwrap();
        writeln!(
            out,
            "pub const {}: {} = {};\n",
            constant.name,
            constant.ty,
            rust_value(&constant.ty, constant.value, &model.newtypes)
        )
        .unwrap();
    }
    for syscall in &model.syscalls {
        writeln!(out, "/// {}", syscall.doc).unwrap();
        writeln!(
            out,
            "pub const DW_SYSCALL_{}: DwSyscallId = DwSyscallId(0x{:08x});\n",
            syscall.name.to_ascii_uppercase(),
            syscall.number
        )
        .unwrap();
    }

    for record in &model.records {
        writeln!(out, "/// {}", record.doc).unwrap();
        writeln!(out, "#[repr(C)]").unwrap();
        writeln!(out, "#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]").unwrap();
        writeln!(out, "pub struct {} {{", record.name).unwrap();
        for field in &record.fields {
            writeln!(out, "    /// {}", field.doc).unwrap();
            writeln!(out, "    pub {}: {},", field.name, field.ty.rust()).unwrap();
        }
        writeln!(out, "}}\n").unwrap();
        writeln!(
            out,
            "pub const {}: u32 = {};\n",
            record_size_constant(&record.name),
            record.size
        )
        .unwrap();
    }

    writeln!(out, "#[cfg(test)]").unwrap();
    writeln!(out, "mod generated_layout_tests {{").unwrap();
    writeln!(out, "    use super::*;").unwrap();
    writeln!(
        out,
        "    use core::mem::{{align_of, offset_of, size_of}};\n"
    )
    .unwrap();
    writeln!(out, "    #[test]").unwrap();
    writeln!(out, "    fn scalar_layouts_match_schema() {{").unwrap();
    let layouts = type_layouts(&model.newtypes);
    for item in &model.newtypes {
        let (size, align) = layouts[&item.name];
        writeln!(
            out,
            "        assert_eq!(size_of::<{}>(), {});",
            item.name, size
        )
        .unwrap();
        writeln!(
            out,
            "        assert_eq!(align_of::<{}>(), {});",
            item.name, align
        )
        .unwrap();
    }
    writeln!(out, "    }}\n").unwrap();
    writeln!(out, "    #[test]").unwrap();
    writeln!(out, "    fn record_layouts_match_schema() {{").unwrap();
    for record in &model.records {
        writeln!(
            out,
            "        assert_eq!(size_of::<{}>(), {});",
            record.name, record.size
        )
        .unwrap();
        writeln!(
            out,
            "        assert_eq!(align_of::<{}>(), {});",
            record.name, record.align
        )
        .unwrap();
        for (field, offset) in record.fields.iter().zip(&record.offsets) {
            writeln!(
                out,
                "        assert_eq!(offset_of!({}, {}), {});",
                record.name, field.name, offset
            )
            .unwrap();
        }
    }
    writeln!(out, "    }}\n").unwrap();
    writeln!(out, "    #[test]").unwrap();
    writeln!(out, "    fn fundamental_constants_match_schema() {{").unwrap();
    writeln!(out, "        assert_eq!(DW_HANDLE_INVALID.0, 0);").unwrap();
    writeln!(
        out,
        "        assert_eq!(DW_ABI_VERSION, {});",
        model.abi.version
    )
    .unwrap();
    for set in &model.value_sets {
        for item in &set.values {
            writeln!(
                out,
                "        assert_eq!({}_{}.0, {});",
                set.prefix, item.name, item.value
            )
            .unwrap();
        }
    }
    for constant in &model.constants {
        if model
            .newtypes
            .iter()
            .any(|newtype| newtype.name == constant.ty)
        {
            writeln!(
                out,
                "        assert_eq!({}.0, {});",
                constant.name, constant.value
            )
            .unwrap();
        } else {
            writeln!(
                out,
                "        assert_eq!({}, {});",
                constant.name, constant.value
            )
            .unwrap();
        }
    }
    for syscall in &model.syscalls {
        writeln!(
            out,
            "        assert_eq!(DW_SYSCALL_{}.0, 0x{:08x});",
            syscall.name.to_ascii_uppercase(),
            syscall.number
        )
        .unwrap();
    }
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    Ok(out)
}

fn rust_value(ty: &str, value: i128, newtypes: &[Newtype]) -> String {
    if newtypes.iter().any(|item| item.name == ty) {
        format!("{ty}({value})")
    } else {
        value.to_string()
    }
}

fn render_c(model: &Model) -> Result<String> {
    let mut out = generated_preamble("/*");
    // Close the deliberately simple block-comment preamble lines.
    out = out.replace("\n\n", " */\n\n").replace("\n/* Do", "\n * Do");
    writeln!(out, "#ifndef DEEPWYRM_ABI_GENERATED_H").unwrap();
    writeln!(out, "#define DEEPWYRM_ABI_GENERATED_H\n").unwrap();
    writeln!(out, "#include <stddef.h>").unwrap();
    writeln!(out, "#include <stdint.h>\n").unwrap();
    writeln!(out, "#if defined(__cplusplus)").unwrap();
    writeln!(out, "#define DW_STATIC_ASSERT static_assert").unwrap();
    writeln!(out, "#define DW_ALIGNOF alignof").unwrap();
    writeln!(out, "#else").unwrap();
    writeln!(out, "#define DW_STATIC_ASSERT _Static_assert").unwrap();
    writeln!(out, "#define DW_ALIGNOF _Alignof").unwrap();
    writeln!(out, "#endif\n").unwrap();
    writeln!(
        out,
        "#define DW_ABI_VERSION UINT32_C({})\n",
        model.abi.version
    )
    .unwrap();
    let layouts = type_layouts(&model.newtypes);
    for item in &model.newtypes {
        writeln!(out, "/* {} */", item.doc).unwrap();
        writeln!(out, "typedef {} {};\n", c_primitive(&item.base)?, item.name).unwrap();
        let (size, align) = layouts[&item.name];
        writeln!(
            out,
            "DW_STATIC_ASSERT(sizeof({}) == {}, \"{} size\");",
            item.name, size, item.name
        )
        .unwrap();
        writeln!(
            out,
            "DW_STATIC_ASSERT(DW_ALIGNOF({}) == {}, \"{} alignment\");\n",
            item.name, align, item.name
        )
        .unwrap();
    }
    for set in &model.value_sets {
        for item in &set.values {
            writeln!(out, "/* {} */", item.doc).unwrap();
            writeln!(
                out,
                "#define {}_{} (({})({}))",
                set.prefix, item.name, set.rust_type, item.value
            )
            .unwrap();
        }
        out.push('\n');
    }
    for constant in &model.constants {
        writeln!(out, "/* {} */", constant.doc).unwrap();
        writeln!(
            out,
            "#define {} (({})({}))",
            constant.name,
            c_named(&constant.ty)?,
            constant.value
        )
        .unwrap();
    }
    out.push('\n');
    for syscall in &model.syscalls {
        writeln!(out, "/* {} */", syscall.doc).unwrap();
        writeln!(
            out,
            "#define DW_SYSCALL_{} ((DwSyscallId)(UINT32_C(0x{:08x})))",
            syscall.name.to_ascii_uppercase(),
            syscall.number
        )
        .unwrap();
    }
    out.push('\n');

    for record in &model.records {
        writeln!(out, "/* {} */", record.doc).unwrap();
        writeln!(out, "typedef struct {} {{", record.name).unwrap();
        for field in &record.fields {
            writeln!(out, "    /* {} */", field.doc).unwrap();
            match &field.ty {
                FieldType::Named(name) => {
                    writeln!(out, "    {} {};", c_named(name)?, field.name).unwrap();
                }
                FieldType::Array(name, count) => {
                    writeln!(out, "    {} {}[{}];", c_named(name)?, field.name, count).unwrap();
                }
            }
        }
        writeln!(out, "}} {};", record.name).unwrap();
        writeln!(
            out,
            "#define {} ((uint32_t)({}))",
            record_size_constant(&record.name),
            record.size
        )
        .unwrap();
        writeln!(
            out,
            "DW_STATIC_ASSERT(sizeof({}) == {}, \"{} size\");",
            record.name, record.size, record.name
        )
        .unwrap();
        writeln!(
            out,
            "DW_STATIC_ASSERT(DW_ALIGNOF({}) == {}, \"{} alignment\");",
            record.name, record.align, record.name
        )
        .unwrap();
        for (field, offset) in record.fields.iter().zip(&record.offsets) {
            writeln!(
                out,
                "DW_STATIC_ASSERT(offsetof({}, {}) == {}, \"{}.{} offset\");",
                record.name, field.name, offset, record.name, field.name
            )
            .unwrap();
        }
        out.push('\n');
    }
    writeln!(out, "#undef DW_ALIGNOF").unwrap();
    writeln!(out, "#undef DW_STATIC_ASSERT\n").unwrap();
    writeln!(out, "#endif /* DEEPWYRM_ABI_GENERATED_H */").unwrap();
    Ok(out)
}

fn c_primitive(name: &str) -> Result<&'static str> {
    match name {
        "u8" => Ok("uint8_t"),
        "u16" => Ok("uint16_t"),
        "u32" => Ok("uint32_t"),
        "u64" => Ok("uint64_t"),
        "i8" => Ok("int8_t"),
        "i16" => Ok("int16_t"),
        "i32" => Ok("int32_t"),
        "i64" => Ok("int64_t"),
        other => Err(Error::new(format!("unsupported C primitive `{other}`"))),
    }
}

fn c_named(name: &str) -> Result<&str> {
    match name {
        "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" => c_primitive(name),
        _ => Ok(name),
    }
}

fn render_dispatch_metadata(model: &Model) -> Result<String> {
    let mut out = generated_preamble("//");
    writeln!(out, "#[derive(Clone, Copy, Debug, Eq, PartialEq)]").unwrap();
    writeln!(out, "pub struct DwSyscallDispatchMetadata {{").unwrap();
    writeln!(out, "    pub number: u32,").unwrap();
    writeln!(out, "    pub name: &'static str,").unwrap();
    writeln!(out, "    pub implementation_phase: &'static str,").unwrap();
    writeln!(out, "    pub argument_count: u8,").unwrap();
    writeln!(out, "}}\n").unwrap();
    writeln!(
        out,
        "pub const DW_SYSCALL_DISPATCH_METADATA: &[DwSyscallDispatchMetadata] = &["
    )
    .unwrap();
    for syscall in &model.syscalls {
        writeln!(out, "    DwSyscallDispatchMetadata {{").unwrap();
        writeln!(out, "        number: 0x{:08x},", syscall.number).unwrap();
        writeln!(out, "        name: \"{}\",", syscall.name).unwrap();
        writeln!(out, "        implementation_phase: \"{}\",", syscall.phase).unwrap();
        writeln!(out, "        argument_count: {},", syscall.arguments.len()).unwrap();
        writeln!(out, "    }},").unwrap();
    }
    writeln!(out, "];\n").unwrap();
    writeln!(
        out,
        "pub const DW_UNKNOWN_SYSCALL_STATUS_NAME: &str = \"NOT_SUPPORTED\";"
    )
    .unwrap();
    Ok(out)
}

fn render_wrapper_metadata(model: &Model) -> Result<String> {
    let mut out = generated_preamble("//");
    writeln!(
        out,
        "pub const DW_SYSCALL_INSTRUCTION: &str = \"{}\";",
        model.abi.instruction
    )
    .unwrap();
    writeln!(
        out,
        "pub const DW_SYSCALL_NUMBER_REGISTER: &str = \"{}\";",
        model.abi.number_register
    )
    .unwrap();
    writeln!(
        out,
        "pub const DW_SYSCALL_RESULT_REGISTER: &str = \"{}\";",
        model.abi.result_register
    )
    .unwrap();
    writeln!(
        out,
        "pub const DW_SYSCALL_CLOBBERS: &str = \"{}\";",
        model.abi.clobbers
    )
    .unwrap();
    writeln!(
        out,
        "pub const DW_SYSCALL_RESULT_RULE: &str = \"{}\";\n",
        model.abi.result_rule
    )
    .unwrap();
    writeln!(out, "#[derive(Clone, Copy, Debug, Eq, PartialEq)]").unwrap();
    writeln!(out, "pub struct DwSyscallArgumentMetadata {{").unwrap();
    writeln!(out, "    pub syscall_number: u32,").unwrap();
    writeln!(out, "    pub index: u8,").unwrap();
    writeln!(out, "    pub register: &'static str,").unwrap();
    writeln!(out, "    pub name: &'static str,").unwrap();
    writeln!(out, "    pub abi_type: &'static str,").unwrap();
    writeln!(out, "    pub direction: &'static str,").unwrap();
    writeln!(out, "    pub required_object_type: &'static str,").unwrap();
    writeln!(out, "    pub required_rights: &'static str,").unwrap();
    writeln!(out, "}}\n").unwrap();
    writeln!(
        out,
        "pub const DW_SYSCALL_ARGUMENT_METADATA: &[DwSyscallArgumentMetadata] = &["
    )
    .unwrap();
    for syscall in &model.syscalls {
        for (index, argument) in syscall.arguments.iter().enumerate() {
            writeln!(out, "    DwSyscallArgumentMetadata {{").unwrap();
            writeln!(out, "        syscall_number: 0x{:08x},", syscall.number).unwrap();
            writeln!(out, "        index: {index},").unwrap();
            writeln!(
                out,
                "        register: \"{}\",",
                model.abi.argument_registers[index]
            )
            .unwrap();
            writeln!(out, "        name: \"{}\",", argument.name).unwrap();
            writeln!(out, "        abi_type: \"{}\",", argument.ty).unwrap();
            writeln!(out, "        direction: \"{}\",", argument.direction).unwrap();
            writeln!(
                out,
                "        required_object_type: \"{}\",",
                argument.object_type
            )
            .unwrap();
            writeln!(
                out,
                "        required_rights: \"{}\",",
                if argument.rights.is_empty() {
                    "NONE".to_owned()
                } else {
                    argument.rights.join("+")
                }
            )
            .unwrap();
            writeln!(out, "    }},").unwrap();
        }
    }
    writeln!(out, "];\n").unwrap();
    Ok(out)
}

fn render_markdown(model: &Model) -> Result<String> {
    let mut out = generated_preamble("<!--");
    out = out.replace("\n\n", " -->\n\n").replace("\n<!-- Do", "\nDo");
    writeln!(
        out,
        "# {} native ABI {}\n",
        model.abi.name, model.abi.version
    )
    .unwrap();
    writeln!(out, "The canonical schema is under `abi/schema`. Numeric namespace values remain representable even when a consumer does not recognize them; operations reject unsupported required values and flags explicitly.\n").unwrap();
    writeln!(out, "## Raw x86_64 syscall convention\n").unwrap();
    writeln!(out, "- Instruction: `{}`", model.abi.instruction).unwrap();
    writeln!(
        out,
        "- Number: `{}` (`DwSyscallId`, zero reserved)",
        model.abi.number_register
    )
    .unwrap();
    writeln!(
        out,
        "- Arguments: `{}`",
        model.abi.argument_registers.join(", ")
    )
    .unwrap();
    writeln!(
        out,
        "- Result: `{}`; {}",
        model.abi.result_register, model.abi.result_rule
    )
    .unwrap();
    writeln!(out, "- Clobbers: `{}`\n", model.abi.clobbers).unwrap();
    writeln!(
        out,
        "## Rights-input invariant\n\n{}\n",
        model.abi.rights_input_rule
    )
    .unwrap();
    for set in &model.value_sets {
        writeln!(out, "## {}\n", title(&set.section)).unwrap();
        writeln!(
            out,
            "| Name | Value | Meaning | Notes |\n|---|---:|---|---|"
        )
        .unwrap();
        for item in &set.values {
            writeln!(
                out,
                "| `{}_{}` | `{}` | {} | {} |",
                set.prefix, item.name, item.value, item.doc, item.extra
            )
            .unwrap();
        }
        out.push('\n');
    }
    writeln!(out, "## Constants\n").unwrap();
    writeln!(out, "| Name | Type | Value | Meaning |\n|---|---|---:|---|").unwrap();
    for constant in &model.constants {
        writeln!(
            out,
            "| `{}` | `{}` | `{}` | {} |",
            constant.name, constant.ty, constant.value, constant.doc
        )
        .unwrap();
    }
    out.push('\n');
    writeln!(out, "## Records\n").unwrap();
    for record in &model.records {
        writeln!(
            out,
            "### `{}`\n\n{} Size {}, alignment {}.\n",
            record.name, record.doc, record.size, record.align
        )
        .unwrap();
        writeln!(
            out,
            "| Offset | Field | Type | Meaning |\n|---:|---|---|---|"
        )
        .unwrap();
        for (field, offset) in record.fields.iter().zip(&record.offsets) {
            writeln!(
                out,
                "| {} | `{}` | `{}` | {} |",
                offset,
                field.name,
                field.ty.rust(),
                field.doc
            )
            .unwrap();
        }
        out.push('\n');
    }
    writeln!(out, "## Object-info topics\n").unwrap();
    writeln!(out, "Unknown topics return `DW_STATUS_NOT_SUPPORTED`.\n").unwrap();
    writeln!(out, "| Topic | Accepted objects | Result | Incompatible object | Meaning |\n|---|---|---|---|---|").unwrap();
    for topic in &model.object_info_topics {
        writeln!(
            out,
            "| `{}` | `{}` | `{}` | `DW_STATUS_{}` | {} |",
            topic.topic, topic.accepted_objects, topic.result, topic.incompatible_status, topic.doc
        )
        .unwrap();
    }
    out.push('\n');
    writeln!(out, "## Syscalls\n").unwrap();
    writeln!(out, "Unknown or debug-disabled syscall IDs return `DW_STATUS_NOT_SUPPORTED`. Fixed-size V1 output pointers write exactly `sizeof(V1)` on success.\n").unwrap();
    for syscall in &model.syscalls {
        writeln!(
            out,
            "### `0x{:08x}` `{}` ({})\n\n{}\n",
            syscall.number, syscall.name, syscall.phase, syscall.doc
        )
        .unwrap();
        if syscall.arguments.is_empty() {
            writeln!(out, "No register arguments.\n").unwrap();
        } else {
            writeln!(out, "| Register | Argument | Type | Direction | Object | Rights |\n|---|---|---|---|---|---|").unwrap();
            for (index, argument) in syscall.arguments.iter().enumerate() {
                writeln!(
                    out,
                    "| `{}` | `{}` | `{}` | {} | {} | {} |",
                    model.abi.argument_registers[index],
                    argument.name,
                    argument.ty,
                    argument.direction,
                    argument.object_type,
                    if argument.rights.is_empty() {
                        "NONE".to_owned()
                    } else {
                        argument.rights.join("+")
                    }
                )
                .unwrap();
            }
            out.push('\n');
        }
    }
    Ok(out)
}

fn title(section: &str) -> String {
    let mut result = String::new();
    for (index, word) in section.split('_').enumerate() {
        if index != 0 {
            result.push(' ');
        }
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            result.push(first.to_ascii_uppercase());
            result.extend(chars);
        }
    }
    result
}

fn render_readme() -> String {
    "# Generated Deepwyrm ABI artifacts\n\nThis directory is owned by `abi-gen`. Do not edit generated files directly.\n\nFrom the Deepwyrm repository root:\n\n```text\ncargo xtask abi generate\ncargo xtask abi check\n```\n\n`check` regenerates the expected files in memory and fails on missing, stale, or unexpected output.\n".to_owned()
}

fn record_size_constant(name: &str) -> String {
    format!("{}_SIZE", camel_to_upper_snake(name))
}

fn camel_to_upper_snake(name: &str) -> String {
    let mut out = String::new();
    let mut previous_lower_or_digit = false;
    for character in name.chars() {
        if character.is_ascii_uppercase() && previous_lower_or_digit {
            out.push('_');
        }
        out.push(character.to_ascii_uppercase());
        previous_lower_or_digit = character.is_ascii_lowercase() || character.is_ascii_digit();
    }
    out
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
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn copy_schema() -> Self {
            let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "deepwyrm-abi-gen-test-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(root.join("abi/schema")).unwrap();
            let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../abi/schema");
            for (name, _) in SCHEMA_FILES {
                fs::copy(source.join(name), root.join("abi/schema").join(name)).unwrap();
            }
            Self(root)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn rewrite(&self, name: &str, operation: impl FnOnce(String) -> String) {
            let path = self.0.join("abi/schema").join(name);
            let input = fs::read_to_string(&path).unwrap();
            fs::write(path, operation(input)).unwrap();
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn load_error(root: &TempRoot) -> String {
        Model::load(root.path()).unwrap_err().to_string()
    }

    #[test]
    fn canonical_schema_renders_deterministically() {
        let root = TempRoot::copy_schema();
        let model = Model::load(root.path()).unwrap();
        let outputs = render(&model).unwrap();
        assert_eq!(outputs, render(&model).unwrap());
        let documentation = &outputs["ABI.md"];
        for name in [
            "DW_BOOT_BASE_PAGE_SIZE",
            "DW_BOOT_MEMORY_RANGE_V1_VERSION",
            "DW_BOOT_MODULE_V1_VERSION",
            "DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1",
            "DW_BOOT_X86_64_PAGING_HANDOFF_V1_VERSION",
            "DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS",
            "DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT",
            "DW_BOOT_FRAMEBUFFER_V1_VERSION",
            "DW_BOOT_ENTROPY_V1_VERSION",
            "DW_BOOT_INFO_V1_VERSION",
            "DW_DEADLINE_NOW",
            "DW_DEADLINE_INFINITE",
            "DW_WAIT_MANY_MAX_ITEMS",
            "DW_HANDLE_TRANSFER_MOVE",
            "DW_CLOCK_MONOTONIC_ACTIVE",
            "DW_OBJECT_INFO_TASK_STATE_V1",
        ] {
            assert!(documentation.contains(name), "ABI.md omitted {name}");
        }
        for output in outputs.values() {
            assert!(!output.contains("DEBUG_WRITE"));
            assert!(!output.contains("debug_write"));
        }
    }

    #[test]
    fn generate_then_check_detects_and_repairs_drift() {
        let root = TempRoot::copy_schema();
        run(["generate", "--root", root.path().to_str().unwrap()]).unwrap();
        run(["check", "--root", root.path().to_str().unwrap()]).unwrap();
        fs::write(root.path().join("abi/generated/deepwyrm_abi.rs"), "stale\n").unwrap();
        let error = run(["check", "--root", root.path().to_str().unwrap()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("deepwyrm_abi.rs: generated content is stale"));
        run(["generate", "--root", root.path().to_str().unwrap()]).unwrap();
        run(["check", "--root", root.path().to_str().unwrap()]).unwrap();
        assert!(!root.path().join("abi/.generated.tmp").exists());
    }

    #[test]
    fn rejects_unknown_key_and_section() {
        let key_root = TempRoot::copy_schema();
        key_root.rewrite("abi.toml", |text| {
            text.replacen(
                "schema_version = 1",
                "schema_version = 1\nunknown_key = 7",
                1,
            )
        });
        assert!(load_error(&key_root).contains("unsupported key `unknown_key`"));

        let section_root = TempRoot::copy_schema();
        section_root.rewrite("rights.toml", |text| {
            format!("{text}\n[[unknown]]\nname = \"X\"\n")
        });
        assert!(load_error(&section_root).contains("unsupported section `[[unknown]]`"));
    }

    #[test]
    fn type_names_allow_only_the_canonical_x86_64_architecture_token() {
        let root = TempRoot::copy_schema();
        root.rewrite("abi.toml", |text| {
            text.replacen(
                "name = \"DwBootX86_64PagingHandoffFlags\"",
                "name = \"DwBootBad_Type\"",
                1,
            )
        });
        assert!(load_error(&root).contains("`DwBootBad_Type` is not a Deepwyrm ABI type name"));
    }

    #[test]
    fn rejects_duplicate_namespace_name_and_value() {
        let root = TempRoot::copy_schema();
        root.rewrite("status.toml", |text| {
            format!("{text}\n[[status]]\nname = \"SUCCESS\"\nvalue = -99\ndoc = \"duplicate\"\n")
        });
        assert!(load_error(&root).contains("duplicate status name `SUCCESS`"));

        let root = TempRoot::copy_schema();
        root.rewrite("status.toml", |text| {
            format!(
                "{text}\n[[status]]\nname = \"ANOTHER_FAILURE\"\nvalue = -1\ndoc = \"duplicate\"\n"
            )
        });
        assert!(load_error(&root).contains("duplicate status value -1"));
    }

    #[test]
    fn rejects_composite_right_and_invalid_object_zero() {
        let root = TempRoot::copy_schema();
        root.rewrite("rights.toml", |text| {
            text.replacen(
                "value = 0x0000000000000001",
                "value = 0x0000000000000003",
                1,
            )
        });
        assert!(load_error(&root).contains("right `READ` value must be one nonzero bit"));

        let root = TempRoot::copy_schema();
        root.rewrite("objects.toml", |text| {
            text.replacen(
                "name = \"TASK_GROUP\"\nvalue = 1",
                "name = \"TASK_GROUP\"\nvalue = 0",
                1,
            )
        });
        assert!(load_error(&root).contains("duplicate object value 0"));
    }

    #[test]
    fn rejects_zero_duplicate_and_overwide_syscall_ids() {
        let root = TempRoot::copy_schema();
        root.rewrite("syscalls.toml", |text| {
            text.replacen("number = 0x00000001", "number = 0", 1)
        });
        assert!(load_error(&root).contains("syscall ID zero is reserved"));

        let root = TempRoot::copy_schema();
        root.rewrite("syscalls.toml", |text| {
            text.replacen("number = 0x00000010", "number = 0x00000001", 1)
        });
        assert!(load_error(&root).contains("duplicate syscall ID 0x00000001"));

        let root = TempRoot::copy_schema();
        root.rewrite("syscalls.toml", |text| {
            text.replacen(
                "arg5 = \"flags|u64|in|NONE|NONE\"",
                "arg5 = \"flags|u64|in|NONE|NONE\"\narg6 = \"extra|u64|in|NONE|NONE\"",
                1,
            )
        });
        assert!(load_error(&root).contains("has 7 arguments; maximum is 6"));

        let root = TempRoot::copy_schema();
        root.rewrite("syscalls.toml", |text| {
            text.replacen("number = 0x00000001", "number = 0xffff0001", 1)
        });
        assert!(load_error(&root).contains("debug/test syscall range is forbidden"));
    }

    #[test]
    fn rejects_missing_or_mismatched_boot_contract_constants() {
        let root = TempRoot::copy_schema();
        root.rewrite("boot.toml", |text| {
            text.replacen(
                "name = \"DW_BOOT_INFO_V1_VERSION\"\ntype = \"u32\"\nvalue = 1",
                "name = \"DW_BOOT_INFO_V1_VERSION\"\ntype = \"u32\"\nvalue = 2",
                1,
            )
        });
        assert!(load_error(&root).contains(
            "boot contract constant `DW_BOOT_INFO_V1_VERSION` must have type u32 and value 1"
        ));

        let root = TempRoot::copy_schema();
        root.rewrite("boot.toml", |text| {
            text.replacen(
                "name = \"DW_BOOT_BASE_PAGE_SIZE\"",
                "name = \"DW_BOOT_PAGE_SIZE_MISSING\"",
                1,
            )
        });
        assert!(load_error(&root).contains(
            "boot contract requires constant `DW_BOOT_BASE_PAGE_SIZE` with type u32 and value 4096"
        ));
    }

    #[test]
    fn generated_c_header_passes_clang_when_available() {
        if Command::new("clang").arg("--version").output().is_err() {
            return;
        }
        let root = TempRoot::copy_schema();
        run(["generate", "--root", root.path().to_str().unwrap()]).unwrap();
        let probe = root.path().join("abi/generated/header_probe.c");
        fs::write(
            &probe,
            "#include \"deepwyrm_abi.h\"\n_Static_assert(DW_STATUS_BAD_ADDRESS == -16, \"status parity\");\n_Static_assert(DW_RIGHT_MODIFY == 512, \"rights parity\");\n_Static_assert(DW_OBJECT_TYPE_TIMER == 8, \"object parity\");\n_Static_assert(DW_SYSCALL_TIMER_CANCEL == 0x00050012, \"syscall parity\");\n_Static_assert(DW_DEADLINE_INFINITE == UINT64_MAX, \"deadline parity\");\n_Static_assert(DW_BOOT_BASE_PAGE_SIZE == UINT32_C(4096), \"boot page parity\");\n_Static_assert(DW_BOOT_INFO_V1_VERSION == UINT32_C(1), \"boot version parity\");\n_Static_assert(DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1 == 3, \"paging module kind parity\");\n_Static_assert(DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE == UINT32_C(112), \"paging header size parity\");\n_Static_assert(DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS == UINT64_C(0xffffff0000000000), \"paging temporary address parity\");\n_Static_assert(DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX == UINT16_C(510), \"paging PML4 parity\");\n_Static_assert(DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT == UINT32_C(4), \"paging minimum frames parity\");\n_Static_assert(DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT == UINT32_C(256), \"paging maximum frames parity\");\nint main(void) {\n    DwDeadline deadline = DW_DEADLINE_INFINITE;\n    uint32_t payload = DW_CHANNEL_MAX_PAYLOAD;\n    DwStatus status = DW_STATUS_SUCCESS;\n    return (deadline == 0 || payload == 0 || status != 0);\n}\n",
        )
        .unwrap();
        let output = Command::new("clang")
            .args(["-std=c11", "-fsyntax-only"])
            .arg(&probe)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "clang stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
