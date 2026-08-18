use super::*;

pub(super) fn validate_boot_contract_constants(
    boot_doc: &Document,
    constants: &[Constant],
) -> Result<()> {
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

pub(super) fn require_u32_constant(constants: &[Constant], name: &str, value: i128) -> Result<()> {
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

pub(super) fn reject_unexpected_schema_files(directory: &Path) -> Result<()> {
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

pub(super) fn require_schema_version(table: &Table) -> Result<()> {
    if table.integer("schema_version")? != 1 {
        return Err(Error::new(format!(
            "{}: unsupported schema_version; expected 1",
            table.label()
        )));
    }
    Ok(())
}

pub(super) fn tables<'a>(document: &'a Document, section: &str) -> &'a [Table] {
    document
        .arrays
        .get(section)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

pub(super) fn as_u32(table: &Table, key: &str) -> Result<u32> {
    u32::try_from(table.integer(key)?).map_err(|_| {
        Error::new(format!(
            "{}: key `{key}` is outside the u32 range",
            table.label()
        ))
    })
}

pub(super) fn load_value_set(
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

pub(super) fn validate_value_sets(sets: &[ValueSet]) -> Result<()> {
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

pub(super) fn load_object_rights(
    document: &Document,
    objects: &ValueSet,
    rights: &ValueSet,
) -> Result<(Vec<ObjectRights>, u64)> {
    document.top.reject_unknown(&["schema_version"], None)?;
    require_schema_version(&document.top)?;

    let known_rights_mask = rights.values.iter().try_fold(0_u64, |mask, right| {
        let value = u64::try_from(right.value)
            .map_err(|_| Error::new(format!("right `{}` does not fit DwRights", right.name)))?;
        Ok::<u64, Error>(mask | value)
    })?;
    let mut seen_objects = BTreeSet::new();
    let mut entries = Vec::new();

    for table in tables(document, "object_rights") {
        table.reject_unknown(&["object", "rights"], None)?;
        let object = table.text("object")?;
        let object_def = objects
            .values
            .iter()
            .find(|item| item.name == object)
            .ok_or_else(|| {
                Error::new(format!(
                    "{}: object-rights entry uses unknown object `{object}`",
                    table.label()
                ))
            })?;
        if object_def.name == "NONE" || matches!(object_def.extra.as_str(), "sentinel" | "reserved")
        {
            return Err(Error::new(format!(
                "{}: sentinel/reserved object `{object}` must not declare compatible rights",
                table.label()
            )));
        }
        if !seen_objects.insert(object.clone()) {
            return Err(Error::new(format!(
                "{}: duplicate object-rights entry for `{object}`",
                table.label()
            )));
        }

        let raw_rights = table.text("rights")?;
        if raw_rights.trim().is_empty() {
            return Err(Error::new(format!(
                "{}: object `{object}` compatible-rights mask must be nonempty",
                table.label()
            )));
        }
        let mut seen_rights = BTreeSet::new();
        let mut names = Vec::new();
        let mut mask = 0_u64;
        for name in raw_rights.split(',').map(str::trim) {
            if name.is_empty() {
                return Err(Error::new(format!(
                    "{}: object `{object}` contains an empty right name",
                    table.label()
                )));
            }
            if !seen_rights.insert(name.to_owned()) {
                return Err(Error::new(format!(
                    "{}: object `{object}` repeats right `{name}`",
                    table.label()
                )));
            }
            let right = rights
                .values
                .iter()
                .find(|item| item.name == name)
                .ok_or_else(|| {
                    Error::new(format!(
                        "{}: object `{object}` uses unknown right `{name}`",
                        table.label()
                    ))
                })?;
            mask |= u64::try_from(right.value).expect("validated DwRights value");
            names.push(name.to_owned());
        }
        if mask == 0 {
            return Err(Error::new(format!(
                "{}: object `{object}` compatible-rights mask must be nonempty",
                table.label()
            )));
        }
        entries.push(ObjectRights {
            object,
            object_value: u32::try_from(object_def.value).expect("validated DwObjectType value"),
            rights: names,
            mask,
        });
    }

    for object in &objects.values {
        if object.name == "NONE" || matches!(object.extra.as_str(), "sentinel" | "reserved") {
            continue;
        }
        if !seen_objects.contains(&object.name) {
            return Err(Error::new(format!(
                "object-rights schema is missing live object `{}`",
                object.name
            )));
        }
    }
    entries.sort_by_key(|entry| entry.object_value);
    Ok((entries, known_rights_mask))
}

pub(super) fn validate_syscall_object_rights(
    syscalls: &[Syscall],
    object_rights: &[ObjectRights],
) -> Result<()> {
    for syscall in syscalls {
        for argument in &syscall.arguments {
            if argument.rights.is_empty() {
                continue;
            }
            let accepts = |entry: &ObjectRights| {
                argument
                    .rights
                    .iter()
                    .all(|right| entry.rights.contains(right))
            };
            let valid = match argument.object_type.as_str() {
                "ANY" => object_rights.iter().any(accepts),
                "NONE" => false,
                object => object_rights
                    .iter()
                    .find(|entry| entry.object == object)
                    .is_some_and(accepts),
            };
            if !valid {
                return Err(Error::new(format!(
                    "syscall `{}` argument `{}` requires rights `{}` incompatible with object `{}`",
                    syscall.name,
                    argument.name,
                    argument.rights.join("+"),
                    argument.object_type
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn primitive_types() -> BTreeSet<String> {
    ["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

pub(super) fn newtype_bases(newtypes: &[Newtype]) -> BTreeMap<String, String> {
    newtypes
        .iter()
        .map(|item| (item.name.clone(), item.base.clone()))
        .collect()
}

pub(super) fn type_layouts(newtypes: &[Newtype]) -> BTreeMap<String, (usize, usize)> {
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

pub(super) fn validate_scalar_value(
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

pub(super) fn load_record(
    table: &Table,
    layouts: &BTreeMap<String, (usize, usize)>,
) -> Result<Record> {
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

pub(super) fn parse_field_type(
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

pub(super) fn field_layout(
    ty: &FieldType,
    layouts: &BTreeMap<String, (usize, usize)>,
) -> (usize, usize) {
    match ty {
        FieldType::Named(name) => layouts[name],
        FieldType::Array(name, count) => (layouts[name].0 * count, layouts[name].1),
    }
}

pub(super) fn align_up(value: usize, align: usize) -> Result<usize> {
    value
        .checked_add(align - 1)
        .map(|value| value & !(align - 1))
        .ok_or_else(|| Error::new("record layout arithmetic overflow"))
}

pub(super) fn load_arguments(
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

pub(super) fn require_upper_name(name: &str, table: &Table) -> Result<()> {
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

pub(super) fn require_snake_name(name: &str, table: &Table) -> Result<()> {
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

pub(super) fn require_camel_type(name: &str, table: &Table) -> Result<()> {
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

pub(super) fn reject_duplicate_names<'a>(
    names: impl Iterator<Item = &'a str>,
    kind: &str,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for name in names {
        if !seen.insert(name) {
            return Err(Error::new(format!("duplicate {kind} name `{name}`")));
        }
    }
    Ok(())
}
