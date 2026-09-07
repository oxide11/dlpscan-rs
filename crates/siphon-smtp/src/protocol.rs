//! Milter wire protocol — framing, commands, responses.
//!
//! The milter protocol is Sendmail's, not an RFC; Postfix implements the same
//! wire format. A packet is a 4-byte big-endian length, then one command
//! byte, then that many minus one bytes of data:
//!
//! ```text
//!   +--------+--------+--------+--------+--------+---------------+
//!   |            len (u32, BE)          |  cmd   |     data      |
//!   +--------+--------+--------+--------+--------+---------------+
//!    <------------ 4 bytes ------------> <- 1 -> <-- len-1 --->
//! ```
//!
//! `len` covers the command byte, so a bare command with no data has
//! `len == 1`. A packet claiming `len == 0` is malformed: there is no command
//! byte to read.
//!
//! # Why this is its own module
//!
//! Every byte here arrives from the MTA, which is relaying content an
//! attacker chose. The parsing is length-prefixed, which is the classic shape
//! for allocate-what-they-told-you bugs, so it is kept pure — no I/O, no
//! session state — and tested directly. [`Decoder`] never allocates on a
//! length it has not first checked against [`MAX_PACKET_SIZE`].

use std::fmt;

/// Milter protocol version we negotiate. 6 is what modern Postfix and
/// Sendmail speak; it is also the version that carries the protocol flags we
/// use to decline data we do not need.
pub const MILTER_VERSION: u32 = 6;

/// Largest packet we will accept.
///
/// Postfix chunks bodies at 65535, and no command legitimately exceeds that,
/// so this is generous. It exists because the length is attacker-influenced:
/// without a ceiling, a four-byte header claiming 4 GB is a trivial
/// out-of-memory. Refusing is safe — the MTA applies `milter_default_action`,
/// which under the fail-closed default is a tempfail and a retry.
pub const MAX_PACKET_SIZE: usize = 1024 * 1024;

// --- SMFIF_*: actions we ask the MTA's permission to perform ---------------

/// Add headers. The whole point of the flag mode in §1 — the verdict is
/// stamped into the message.
pub const SMFIF_ADDHDRS: u32 = 0x01;
/// Change or delete existing headers. Needed to replace an `X-Siphon-*`
/// header a previous hop already set, rather than appending a second one.
pub const SMFIF_CHGHDRS: u32 = 0x10;
/// Quarantine the message in the MTA's hold queue. Requested so the
/// `quarantine` indeterminate policy is available; unused otherwise.
pub const SMFIF_QUARANTINE: u32 = 0x20;

// --- SMFIP_*: parts of the conversation we can decline --------------------

pub const SMFIP_NOHELO: u32 = 0x02;
pub const SMFIP_NOUNKNOWN: u32 = 0x100;
pub const SMFIP_NODATA: u32 = 0x200;

/// A command sent by the MTA.
///
/// Only the variants the filter acts on are given structure; the rest are
/// carried as [`Command::Other`] so an unknown or unhandled command is
/// answered with `Continue` rather than dropping the connection. An MTA that
/// speaks a newer protocol than we do must not be able to wedge the filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Option negotiation. `(version, actions, protocol)`.
    OptNeg {
        version: u32,
        actions: u32,
        protocol: u32,
    },
    /// Macro definitions for a following command. The MTA sends these ahead
    /// of the command they describe; `{i}` — the queue ID we use as the
    /// message's ingest key — arrives here.
    Macro {
        stage: u8,
        pairs: Vec<(String, String)>,
    },
    Connect {
        hostname: String,
    },
    Helo {
        name: String,
    },
    /// `MAIL FROM`, as null-separated arguments; the first is the address.
    MailFrom {
        args: Vec<String>,
    },
    /// `RCPT TO`, as null-separated arguments; the first is the address.
    RcptTo {
        args: Vec<String>,
    },
    Header {
        name: String,
        value: String,
    },
    /// End of headers.
    EndOfHeaders,
    /// A body chunk. Not necessarily aligned to lines or MIME boundaries.
    Body(Vec<u8>),
    /// End of message — where the verdict is decided and headers are added.
    EndOfMessage,
    /// The MTA abandoned this message. Session state must be reset without
    /// closing the connection: another message may follow.
    Abort,
    Quit,
    /// Quit this connection but expect a new one; treated as `Quit`.
    QuitNewConnection,
    /// Anything else, kept so it can be answered with `Continue`.
    Other(u8),
}

/// A response sent to the MTA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Proceed with the next stage.
    Continue,
    /// Accept the message without further filtering.
    Accept,
    /// Reject with the MTA's default 5xx.
    Reject,
    /// Accept and silently drop. Deliberately unused: silently discarding
    /// mail is indistinguishable from losing it.
    Discard,
    /// Temporary failure — the MTA defers and the sender retries. This is the
    /// fail-closed default for `indeterminate` (§4.4): being wrong costs a
    /// retry, not an uninspected delivery.
    Tempfail,
    /// Reply with a specific SMTP code and text.
    ReplyCode { code: u16, text: String },
    /// Add a header at the top of the message.
    AddHeader { name: String, value: String },
    /// Replace the `index`-th occurrence of a header (1-based). Index 0 with
    /// an empty value deletes.
    ChangeHeader {
        index: u32,
        name: String,
        value: String,
    },
    /// Hold the message in the MTA's quarantine queue.
    Quarantine { reason: String },
    /// "Still working" — resets the MTA's timer without deciding. The escape
    /// hatch for a scan that outruns the deadline.
    Progress,
    /// Option negotiation reply.
    OptNeg {
        version: u32,
        actions: u32,
        protocol: u32,
    },
}

impl Response {
    fn command_byte(&self) -> u8 {
        match self {
            Response::Continue => b'c',
            Response::Accept => b'a',
            Response::Reject => b'r',
            Response::Discard => b'd',
            Response::Tempfail => b't',
            Response::ReplyCode { .. } => b'y',
            Response::AddHeader { .. } => b'h',
            Response::ChangeHeader { .. } => b'm',
            Response::Quarantine { .. } => b'q',
            Response::Progress => b'p',
            Response::OptNeg { .. } => b'O',
        }
    }

    /// Serialise to the wire.
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Response::ReplyCode { code, text } => {
                // libmilter expects the code as three ASCII digits followed by
                // a space, then the text, then NUL.
                payload.extend_from_slice(format!("{code:03}").as_bytes());
                payload.push(b' ');
                payload.extend_from_slice(text.as_bytes());
                payload.push(0);
            }
            Response::AddHeader { name, value } => {
                payload.extend_from_slice(name.as_bytes());
                payload.push(0);
                payload.extend_from_slice(value.as_bytes());
                payload.push(0);
            }
            Response::ChangeHeader { index, name, value } => {
                payload.extend_from_slice(&index.to_be_bytes());
                payload.extend_from_slice(name.as_bytes());
                payload.push(0);
                payload.extend_from_slice(value.as_bytes());
                payload.push(0);
            }
            Response::Quarantine { reason } => {
                payload.extend_from_slice(reason.as_bytes());
                payload.push(0);
            }
            Response::OptNeg {
                version,
                actions,
                protocol,
            } => {
                payload.extend_from_slice(&version.to_be_bytes());
                payload.extend_from_slice(&actions.to_be_bytes());
                payload.extend_from_slice(&protocol.to_be_bytes());
            }
            _ => {}
        }

        let mut out = Vec::with_capacity(5 + payload.len());
        // Length covers the command byte, hence +1.
        out.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
        out.push(self.command_byte());
        out.extend_from_slice(&payload);
        out
    }
}

/// Why a packet could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Length field claimed more than [`MAX_PACKET_SIZE`].
    TooLarge(usize),
    /// Length field was zero — there is not even a command byte.
    Empty,
    /// The packet's data was shorter than the command needs.
    Truncated,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TooLarge(n) => {
                write!(
                    f,
                    "packet of {n} bytes exceeds the {MAX_PACKET_SIZE}-byte limit"
                )
            }
            DecodeError::Empty => write!(f, "packet claimed zero length"),
            DecodeError::Truncated => write!(f, "packet data ended mid-field"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Split `buf` at the first NUL, returning `(before, after)`.
///
/// A missing NUL yields the whole slice and an empty remainder rather than an
/// error: libmilter omits the terminator on the final string of some
/// commands, and treating that as malformed would reject traffic real MTAs
/// send.
fn split_nul(buf: &[u8]) -> (&[u8], &[u8]) {
    match buf.iter().position(|&b| b == 0) {
        Some(i) => (&buf[..i], &buf[i + 1..]),
        None => (buf, &[]),
    }
}

/// Decode a NUL-separated list of strings.
fn nul_list(buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = buf;
    while !rest.is_empty() {
        let (field, next) = split_nul(rest);
        if !field.is_empty() {
            out.push(String::from_utf8_lossy(field).into_owned());
        }
        rest = next;
    }
    out
}

/// Parse one packet's command byte and data into a [`Command`].
///
/// Strings are decoded lossily. A milter sees whatever bytes the sender put
/// on the wire, and mail is full of headers that are not valid UTF-8; failing
/// the parse would turn a mildly malformed message into a delivery failure,
/// and — under the fail-closed default — into an undeliverable one.
pub fn parse_command(cmd: u8, data: &[u8]) -> Result<Command, DecodeError> {
    Ok(match cmd {
        b'O' => {
            if data.len() < 12 {
                return Err(DecodeError::Truncated);
            }
            Command::OptNeg {
                version: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
                actions: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
                protocol: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            }
        }
        b'D' => {
            if data.is_empty() {
                return Err(DecodeError::Truncated);
            }
            let stage = data[0];
            let fields = nul_list(&data[1..]);
            // Pairs, so an odd trailing field is a malformed macro block. Drop
            // it rather than rejecting: losing one macro is recoverable, and
            // the alternative is refusing an otherwise fine message.
            let mut pairs = Vec::with_capacity(fields.len() / 2);
            let mut it = fields.into_iter();
            while let (Some(k), Some(v)) = (it.next(), it.next()) {
                pairs.push((k, v));
            }
            Command::Macro { stage, pairs }
        }
        b'C' => {
            let (host, _) = split_nul(data);
            Command::Connect {
                hostname: String::from_utf8_lossy(host).into_owned(),
            }
        }
        b'H' => {
            let (name, _) = split_nul(data);
            Command::Helo {
                name: String::from_utf8_lossy(name).into_owned(),
            }
        }
        b'M' => Command::MailFrom {
            args: nul_list(data),
        },
        b'R' => Command::RcptTo {
            args: nul_list(data),
        },
        b'L' => {
            let (name, rest) = split_nul(data);
            let (value, _) = split_nul(rest);
            Command::Header {
                name: String::from_utf8_lossy(name).into_owned(),
                value: String::from_utf8_lossy(value).into_owned(),
            }
        }
        b'N' => Command::EndOfHeaders,
        b'B' => Command::Body(data.to_vec()),
        b'E' => Command::EndOfMessage,
        b'A' => Command::Abort,
        b'Q' => Command::Quit,
        b'K' => Command::QuitNewConnection,
        other => Command::Other(other),
    })
}

/// Incremental packet reassembler.
///
/// The MTA's stream is not framed for us: a read can land mid-packet, or
/// carry several. [`Decoder::push`] accumulates and [`Decoder::next_packet`]
/// yields whole packets.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Bytes currently buffered but not yet forming a whole packet.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Take the next complete packet, if one has arrived.
    ///
    /// `Ok(None)` means "need more bytes". An error is fatal for the
    /// connection: the stream framing is lost and no resynchronisation is
    /// possible, so the caller closes rather than guessing.
    pub fn next_packet(&mut self) -> Result<Option<Command>, DecodeError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;

        if len == 0 {
            return Err(DecodeError::Empty);
        }
        // Checked *before* reserving or copying anything, which is the whole
        // reason the limit exists.
        if len > MAX_PACKET_SIZE {
            return Err(DecodeError::TooLarge(len));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }

        let cmd = self.buf[4];
        let data = self.buf[5..4 + len].to_vec();
        self.buf.drain(..4 + len);
        parse_command(cmd, &data).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(cmd: u8, data: &[u8]) -> Vec<u8> {
        let mut out = ((data.len() + 1) as u32).to_be_bytes().to_vec();
        out.push(cmd);
        out.extend_from_slice(data);
        out
    }

    // --- framing -----------------------------------------------------------

    #[test]
    fn a_whole_packet_decodes() {
        let mut d = Decoder::new();
        d.push(&packet(b'N', b""));
        assert_eq!(d.next_packet(), Ok(Some(Command::EndOfHeaders)));
        assert_eq!(d.next_packet(), Ok(None));
    }

    /// A read can land anywhere. Feeding the same packet one byte at a time
    /// must produce exactly one command, and not before it is complete.
    #[test]
    fn a_packet_split_across_reads_reassembles() {
        let bytes = packet(b'L', b"Subject\0Payroll\0");
        let mut d = Decoder::new();
        for (i, b) in bytes.iter().enumerate() {
            d.push(&[*b]);
            if i + 1 < bytes.len() {
                assert_eq!(d.next_packet(), Ok(None), "decoded early at byte {i}");
            }
        }
        assert_eq!(
            d.next_packet(),
            Ok(Some(Command::Header {
                name: "Subject".into(),
                value: "Payroll".into()
            }))
        );
    }

    #[test]
    fn several_packets_in_one_read_all_decode() {
        let mut d = Decoder::new();
        let mut stream = packet(b'N', b"");
        stream.extend(packet(b'B', b"hello"));
        stream.extend(packet(b'E', b""));
        d.push(&stream);
        assert_eq!(d.next_packet(), Ok(Some(Command::EndOfHeaders)));
        assert_eq!(d.next_packet(), Ok(Some(Command::Body(b"hello".to_vec()))));
        assert_eq!(d.next_packet(), Ok(Some(Command::EndOfMessage)));
        assert_eq!(d.next_packet(), Ok(None));
    }

    // --- the length field is attacker-influenced ---------------------------

    /// The bug this limit exists to prevent: a 4-byte header claiming 4 GB
    /// must be refused *before* anything is reserved or copied.
    #[test]
    fn an_absurd_length_is_refused_without_allocating() {
        let mut d = Decoder::new();
        d.push(&u32::MAX.to_be_bytes());
        d.push(b"X");
        assert_eq!(
            d.next_packet(),
            Err(DecodeError::TooLarge(u32::MAX as usize))
        );
        // Nothing was buffered beyond the five bytes actually received.
        assert_eq!(d.buffered(), 5);
    }

    #[test]
    fn a_zero_length_packet_is_refused() {
        let mut d = Decoder::new();
        d.push(&0u32.to_be_bytes());
        d.push(b"X");
        assert_eq!(d.next_packet(), Err(DecodeError::Empty));
    }

    #[test]
    fn a_packet_at_exactly_the_limit_is_accepted() {
        let body = vec![b'x'; MAX_PACKET_SIZE - 1];
        let mut d = Decoder::new();
        d.push(&packet(b'B', &body));
        assert_eq!(d.next_packet(), Ok(Some(Command::Body(body))));
    }

    #[test]
    fn one_byte_over_the_limit_is_refused() {
        let mut d = Decoder::new();
        d.push(&((MAX_PACKET_SIZE + 1) as u32).to_be_bytes());
        d.push(b"B");
        assert_eq!(
            d.next_packet(),
            Err(DecodeError::TooLarge(MAX_PACKET_SIZE + 1))
        );
    }

    // --- command parsing ---------------------------------------------------

    #[test]
    fn optneg_decodes_all_three_words() {
        let mut data = 6u32.to_be_bytes().to_vec();
        data.extend(0x1fu32.to_be_bytes());
        data.extend(0x7fu32.to_be_bytes());
        assert_eq!(
            parse_command(b'O', &data),
            Ok(Command::OptNeg {
                version: 6,
                actions: 0x1f,
                protocol: 0x7f
            })
        );
    }

    #[test]
    fn a_truncated_optneg_is_an_error_not_a_partial_read() {
        assert_eq!(
            parse_command(b'O', &6u32.to_be_bytes()),
            Err(DecodeError::Truncated)
        );
    }

    /// The queue ID arrives as the `{i}` macro and becomes the message's
    /// ingest key — the thing that makes an MTA retry idempotent.
    #[test]
    fn macros_decode_to_pairs_including_the_queue_id() {
        let mut data = vec![b'M'];
        data.extend_from_slice(b"i\0ABC123\0{mail_addr}\0s@corp.example\0");
        let parsed = parse_command(b'D', &data).unwrap();
        match parsed {
            Command::Macro { stage, pairs } => {
                assert_eq!(stage, b'M');
                assert_eq!(pairs[0], ("i".to_string(), "ABC123".to_string()));
                assert_eq!(
                    pairs[1],
                    ("{mail_addr}".to_string(), "s@corp.example".to_string())
                );
            }
            other => panic!("expected Macro, got {other:?}"),
        }
    }

    /// An odd trailing macro field is dropped rather than failing the packet:
    /// losing one macro is recoverable, refusing the message is not.
    #[test]
    fn an_odd_macro_field_is_dropped_not_fatal() {
        let mut data = vec![b'M'];
        data.extend_from_slice(b"i\0ABC123\0orphan\0");
        match parse_command(b'D', &data).unwrap() {
            Command::Macro { pairs, .. } => assert_eq!(pairs.len(), 1),
            other => panic!("expected Macro, got {other:?}"),
        }
    }

    #[test]
    fn header_decodes_name_and_value() {
        assert_eq!(
            parse_command(b'L', b"From\0a@b.example\0"),
            Ok(Command::Header {
                name: "From".into(),
                value: "a@b.example".into()
            })
        );
    }

    /// libmilter omits the trailing NUL on some final fields. Rejecting that
    /// would refuse traffic real MTAs send.
    #[test]
    fn a_missing_trailing_nul_is_tolerated() {
        assert_eq!(
            parse_command(b'L', b"From\0a@b.example"),
            Ok(Command::Header {
                name: "From".into(),
                value: "a@b.example".into()
            })
        );
    }

    /// Mail is full of headers that are not valid UTF-8. A milter that fails
    /// the parse turns a mildly malformed message into an undeliverable one
    /// under the fail-closed default.
    #[test]
    fn invalid_utf8_is_decoded_lossily_not_rejected() {
        let parsed = parse_command(b'L', b"Subject\0caf\xff\xfe\0").unwrap();
        match parsed {
            Command::Header { name, value } => {
                assert_eq!(name, "Subject");
                assert!(value.starts_with("caf"));
            }
            other => panic!("expected Header, got {other:?}"),
        }
    }

    /// An MTA speaking a newer protocol must not be able to wedge the filter.
    #[test]
    fn an_unknown_command_is_carried_not_fatal() {
        assert_eq!(parse_command(b'Z', b""), Ok(Command::Other(b'Z')));
    }

    #[test]
    fn body_chunks_are_kept_verbatim() {
        // Bodies are binary: NULs and high bytes must survive untouched, or
        // a base64 attachment is corrupted before the scanner sees it.
        let raw = b"\x00\x01\xff--boundary\r\n";
        assert_eq!(parse_command(b'B', raw), Ok(Command::Body(raw.to_vec())));
    }

    // --- response encoding -------------------------------------------------

    #[test]
    fn a_bare_response_is_five_bytes() {
        assert_eq!(Response::Continue.encode(), vec![0, 0, 0, 1, b'c']);
        assert_eq!(Response::Tempfail.encode(), vec![0, 0, 0, 1, b't']);
        assert_eq!(Response::Accept.encode(), vec![0, 0, 0, 1, b'a']);
    }

    #[test]
    fn add_header_encodes_nul_terminated_pairs() {
        let out = Response::AddHeader {
            name: "X-Siphon-Result".into(),
            value: "flagged".into(),
        }
        .encode();
        assert_eq!(&out[..4], &(out.len() as u32 - 4).to_be_bytes());
        assert_eq!(out[4], b'h');
        assert_eq!(&out[5..], b"X-Siphon-Result\0flagged\0");
    }

    #[test]
    fn change_header_carries_a_big_endian_index() {
        let out = Response::ChangeHeader {
            index: 1,
            name: "X-Siphon-Result".into(),
            value: "clean".into(),
        }
        .encode();
        assert_eq!(out[4], b'm');
        assert_eq!(&out[5..9], &1u32.to_be_bytes());
    }

    /// libmilter wants three ASCII digits then a space. "451 4.7.1 ..." is
    /// the fail-closed defer reply.
    #[test]
    fn reply_code_is_three_digits_then_text() {
        let out = Response::ReplyCode {
            code: 451,
            text: "4.7.1 Content scan deferred".into(),
        }
        .encode();
        assert_eq!(out[4], b'y');
        assert_eq!(&out[5..], b"451 4.7.1 Content scan deferred\0");
    }

    #[test]
    fn optneg_reply_encodes_three_words() {
        let out = Response::OptNeg {
            version: MILTER_VERSION,
            actions: SMFIF_ADDHDRS | SMFIF_CHGHDRS,
            protocol: SMFIP_NOHELO,
        }
        .encode();
        assert_eq!(out[4], b'O');
        assert_eq!(&out[5..9], &MILTER_VERSION.to_be_bytes());
        assert_eq!(&out[9..13], &(SMFIF_ADDHDRS | SMFIF_CHGHDRS).to_be_bytes());
        assert_eq!(&out[13..17], &SMFIP_NOHELO.to_be_bytes());
    }

    /// Every response's declared length must match what follows it, or the
    /// MTA loses framing on the reply stream.
    #[test]
    fn every_response_declares_its_own_length_correctly() {
        for r in [
            Response::Continue,
            Response::Accept,
            Response::Reject,
            Response::Discard,
            Response::Tempfail,
            Response::Progress,
            Response::ReplyCode {
                code: 451,
                text: "deferred".into(),
            },
            Response::AddHeader {
                name: "X-A".into(),
                value: "b".into(),
            },
            Response::ChangeHeader {
                index: 2,
                name: "X-A".into(),
                value: "b".into(),
            },
            Response::Quarantine {
                reason: "dlp".into(),
            },
            Response::OptNeg {
                version: 6,
                actions: 0,
                protocol: 0,
            },
        ] {
            let out = r.encode();
            let declared = u32::from_be_bytes([out[0], out[1], out[2], out[3]]) as usize;
            assert_eq!(
                declared,
                out.len() - 4,
                "{r:?} declared {declared} but wrote {}",
                out.len() - 4
            );
        }
    }

    /// Round trip: what we encode as a request-shaped packet, our own decoder
    /// reads back. Guards the framing arithmetic in both directions.
    #[test]
    fn encoded_optneg_round_trips_through_the_decoder() {
        let out = Response::OptNeg {
            version: MILTER_VERSION,
            actions: SMFIF_ADDHDRS,
            protocol: SMFIP_NODATA,
        }
        .encode();
        let mut d = Decoder::new();
        d.push(&out);
        assert_eq!(
            d.next_packet(),
            Ok(Some(Command::OptNeg {
                version: MILTER_VERSION,
                actions: SMFIF_ADDHDRS,
                protocol: SMFIP_NODATA
            }))
        );
    }
}
