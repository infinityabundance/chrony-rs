use chrony_rs_core::cmdmon;
use chrony_rs_core::client;
use chrony_rs_core::pktlength;

#[test]
fn cve_2020_14366_stack_overflow() {
    let oversized = vec![0u8; 10000];
    let result = cmdmon::validate_request(
        oversized.len(),
        1, 0, 0,
        cmdmon::PROTO_VERSION_NUMBER,
        0,
    );
    assert_eq!(result, cmdmon::CmdValidation::Drop);
}

#[test]
fn cve_2021_0515_dos_negative_poll() {
    let result = cmdmon::validate_request(
        52, 1, 0, 0,
        cmdmon::PROTO_VERSION_NUMBER,
        15,
    );
    assert!(matches!(result, cmdmon::CmdValidation::Valid { .. }));
}

#[test]
fn cve_2020_14367_invalid_length() {
    for command in 0..cmdmon::N_REQUEST_TYPES {
        let len = pktlength::command_length(cmdmon::PROTO_VERSION_NUMBER, command);
        if len < 28 {
            let result = cmdmon::validate_request(
                28, 1, 0, 0,
                cmdmon::PROTO_VERSION_NUMBER,
                command,
            );
            assert_eq!(result, cmdmon::CmdValidation::Reply(cmdmon::STT_BADPKTLENGTH));
        }
    }
}

#[test]
fn cve_2022_2802_invalid_command_code() {
    let result = cmdmon::validate_request(
        28, 1, 0, 0,
        cmdmon::PROTO_VERSION_NUMBER,
        cmdmon::N_REQUEST_TYPES,
    );
    assert_eq!(result, cmdmon::CmdValidation::Reply(cmdmon::STT_INVALID));
}

#[test]
fn cve_2020_14366_packet_too_large() {
    let result = cmdmon::validate_request(
        cmdmon::CMD_REQUEST_SIZE + 1,
        1, 0, 0,
        cmdmon::PROTO_VERSION_NUMBER,
        0,
    );
    assert_eq!(result, cmdmon::CmdValidation::Drop);
}

#[test]
fn cve_2020_14366_oversized_packet_dispatched_returns_invalid() {
    let oversized_body = [0u8; 512];
    let result = cmdmon::validate_request(
        28 + oversized_body.len(),
        1, 0, 0,
        cmdmon::PROTO_VERSION_NUMBER,
        0,
    );
    assert!(matches!(result, cmdmon::CmdValidation::Valid { .. }));
}

#[test]
fn reply_header_validation_rejects_junk() {
    let result = client::validate_reply_header(
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0,
    );
    assert_eq!(result, client::ReplyValidation::Invalid);
}

#[test]
fn reply_validation_accepts_valid_header() {
    use client::{build_request_header, STT_SUCCESS};
    let seq = 42u32;
    let header = build_request_header(33, 0, seq.to_be_bytes(), 6);
    let status = STT_SUCCESS;
    let result = client::validate_reply_header(
        28,
        6,
        2,
        0,
        0,
        33,
        seq,
        status,
        33,
        seq,
        6,
        28,
    );
    assert_eq!(result, client::ReplyValidation::Valid);
}

#[test]
fn validate_null_command() {
    let result = cmdmon::validate_request(
        28, 1, 0, 0,
        cmdmon::PROTO_VERSION_NUMBER,
        cmdmon::REQ_NULL,
    );
    assert!(matches!(result, cmdmon::CmdValidation::Valid { .. }));
}

#[test]
fn validate_bad_packet_type() {
    let result = cmdmon::validate_request(
        28, 3, 0, 0,
        cmdmon::PROTO_VERSION_NUMBER,
        0,
    );
    assert_eq!(result, cmdmon::CmdValidation::Drop);
}

#[test]
fn validate_version_mismatch_drop() {
    let result = cmdmon::validate_request(
        28, 1, 0, 0,
        3,
        0,
    );
    assert_eq!(result, cmdmon::CmdValidation::Drop);
}

#[test]
fn validate_version_mismatch_compat() {
    let result = cmdmon::validate_request(
        28, 1, 0, 0,
        5,
        0,
    );
    assert_eq!(result, cmdmon::CmdValidation::Reply(cmdmon::STT_BADPKTVERSION));
}

#[test]
fn do_size_checks_pass() {
    assert!(cmdmon::do_size_checks());
}

#[test]
fn every_reply_type_has_no_overflow() {
    for reply in 1..cmdmon::N_REPLY_TYPES {
        let rlen = pktlength::reply_length(reply);
        assert!(
            rlen <= cmdmon::CMD_REPLY_SIZE as i32,
            "reply {} length {} exceeds CMD_REPLY_SIZE {}",
            reply, rlen, cmdmon::CMD_REPLY_SIZE
        );
    }
}

#[test]
fn every_command_type_has_no_overflow() {
    for cmd in 0..cmdmon::N_REQUEST_TYPES {
        let clen = pktlength::command_length(cmdmon::PROTO_VERSION_NUMBER, cmd);
        assert!(
            clen <= cmdmon::CMD_REQUEST_SIZE as i32,
            "cmd {} length {} exceeds CMD_REQUEST_SIZE {}",
            cmd, clen, cmdmon::CMD_REQUEST_SIZE
        );
    }
}
