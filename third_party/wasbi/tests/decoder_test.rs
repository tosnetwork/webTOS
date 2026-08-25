//! Decoder edge-case tests.

use wasbi::decoder::decode;
use wasbi::types::ErrorLayer;

const VALID_HEADER: &[u8] = &[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

#[test]
fn decode_empty_module() {
    let module = decode(VALID_HEADER).unwrap();
    assert!(module.get_start_func().is_none());
    assert!(module.get_exports().is_empty());
}

#[test]
fn decode_invalid_magic() {
    let bytes = &[0xFF, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    let err = decode(bytes).err().expect("expected error");
    assert!(err.is_decode_error());
    assert_eq!(err.layer(), ErrorLayer::Decode);
}

#[test]
fn decode_truncated_magic() {
    let err = decode(&[0x00, 0x61]).err().expect("expected error");
    assert!(err.is_decode_error());
}

#[test]
fn decode_wrong_version() {
    let bytes = &[0x00, 0x61, 0x73, 0x6D, 0x02, 0x00, 0x00, 0x00];
    let err = decode(bytes).err().expect("expected error");
    assert!(err.is_decode_error());
}

#[test]
fn decode_empty_bytes() {
    let err = decode(&[]).err().expect("expected error");
    assert!(err.is_decode_error());
}

#[test]
fn decode_only_magic_no_version() {
    let err = decode(&[0x00, 0x61, 0x73, 0x6D])
        .err()
        .expect("expected error");
    assert!(err.is_decode_error());
}

#[test]
fn decode_module_with_type_section() {
    let mut buf = Vec::from(VALID_HEADER);
    buf.push(0x01);
    buf.push(0x04);
    buf.push(0x01);
    buf.push(0x60);
    buf.push(0x00);
    buf.push(0x00);

    let module = decode(&buf).unwrap();
    assert_eq!(module.get_func_types().len(), 1);
    assert_eq!(module.get_func_types()[0].param_count, 0);
    assert_eq!(module.get_func_types()[0].result_count, 0);
}

#[test]
fn decode_module_with_memory() {
    let mut buf = Vec::from(VALID_HEADER);
    buf.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);

    let module = decode(&buf).unwrap();
    assert_eq!(module.get_memories().len(), 1);
    assert_eq!(module.get_memories()[0].min_pages, 1);
}

#[test]
fn decode_module_with_globals() {
    let mut buf = Vec::from(VALID_HEADER);
    buf.extend_from_slice(&[0x06, 0x06, 0x01, 0x7F, 0x00, 0x41, 0x2A, 0x0B]);

    let module = decode(&buf).unwrap();
    assert_eq!(module.get_globals().len(), 1);
    assert!(!module.get_globals()[0].mutable);
}

#[test]
fn decode_module_with_export() {
    let mut buf = Vec::from(VALID_HEADER);
    buf.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    buf.push(0x07);
    buf.push(0x05);
    buf.push(0x01);
    buf.push(0x01);
    buf.push(b'f');
    buf.push(0x00);
    buf.push(0x00);
    buf.extend_from_slice(&[0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B]);

    let module = decode(&buf).unwrap();
    assert_eq!(module.get_exports().len(), 1);
    assert!(module.find_export_func(b"f").is_some());
    assert!(module.find_export_func(b"g").is_none());
}

#[test]
fn decode_module_with_start_function() {
    let mut buf = Vec::from(VALID_HEADER);
    buf.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    buf.extend_from_slice(&[0x08, 0x01, 0x00]);
    buf.extend_from_slice(&[0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B]);

    let module = decode(&buf).unwrap();
    assert_eq!(module.get_start_func(), Some(0));
}

#[test]
fn decode_module_with_data_segment() {
    let mut buf = Vec::from(VALID_HEADER);
    buf.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);
    buf.extend_from_slice(&[0x0C, 0x01, 0x01]);
    buf.extend_from_slice(&[0x0B, 0x07, 0x01, 0x00, 0x41, 0x00, 0x0B, 0x01, 0x42]);

    let module = decode(&buf).unwrap();
    assert_eq!(module.get_data_segments().len(), 1);
    assert!(module.get_data_segments()[0].is_active);
}

#[test]
fn decode_module_with_import() {
    let mut buf = Vec::from(VALID_HEADER);
    buf.extend_from_slice(&[0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F]);
    buf.extend_from_slice(&[0x02, 0x07, 0x01, 0x01, b'e', 0x01, b'f', 0x00, 0x00]);

    let module = decode(&buf).unwrap();
    assert_eq!(module.get_imports().len(), 1);
    assert_eq!(module.func_import_count(), 1);
}
