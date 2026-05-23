use std::io::{self, Read, Write};
use std::net::TcpStream;

use aegis_protocol::wire::{
    HotFrameHeader, HotFrameValidationContext, LayoutSpec, MAX_HOT_HEADER_LEN, read_i64_le,
    read_u16_le, read_u64_le, read_variable_index_entry, split_payload, validate_hot_frame,
    validate_variable_index_table, variable_str_view, variable_view,
};
use aegis_protocol::{
    BudgetSlot, CapabilityBinding, CapabilitySlot, Error, MessageType, ReplayWindow,
    ResourceBudget, StreamSlot, TypeSlot,
};

pub const CAPTURE_PAYMENT_TYPE: MessageType = MessageType::new(0x2101);
pub const CAPTURE_PAYMENT_CAPABILITY: CapabilitySlot = CapabilitySlot::new(7);
pub const REQUEST_TYPE_SLOT: TypeSlot = TypeSlot::new(1);
pub const ACK_TYPE_SLOT: TypeSlot = TypeSlot::new(2);
pub const STREAM: StreamSlot = StreamSlot::new(1);
pub const BUDGET: BudgetSlot = BudgetSlot::new(1);

pub const REQUEST_LAYOUT: LayoutSpec = LayoutSpec {
    required_fixed_len: 26,
    optional_bitmap_len: 1,
    optional_fixed_len: 0,
    variable_index_len: 16,
};

pub const ACK_LAYOUT: LayoutSpec = LayoutSpec {
    required_fixed_len: 8,
    optional_bitmap_len: 0,
    optional_fixed_len: 0,
    variable_index_len: 0,
};

#[derive(Debug, PartialEq, Eq)]
pub struct CapturePayment {
    pub merchant_id: u64,
    pub invoice_id: u64,
    pub amount_cents: i64,
    pub currency: u16,
    pub idempotency_key: Vec<u8>,
    pub reference: String,
}

pub fn build_capture_payment_payload(message: &CapturePayment) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&message.merchant_id.to_le_bytes());
    payload.extend_from_slice(&message.invoice_id.to_le_bytes());
    payload.extend_from_slice(&message.amount_cents.to_le_bytes());
    payload.extend_from_slice(&message.currency.to_le_bytes());
    payload.push(1);

    let idempotency_offset = 0u32;
    let idempotency_len = message.idempotency_key.len() as u32;
    let reference_offset = idempotency_len;
    let reference_len = message.reference.len() as u32;
    payload.extend_from_slice(&idempotency_offset.to_le_bytes());
    payload.extend_from_slice(&idempotency_len.to_le_bytes());
    payload.extend_from_slice(&reference_offset.to_le_bytes());
    payload.extend_from_slice(&reference_len.to_le_bytes());
    payload.extend_from_slice(&message.idempotency_key);
    payload.extend_from_slice(message.reference.as_bytes());
    payload
}

pub fn decode_capture_payment(payload: &[u8]) -> aegis_protocol::Result<CapturePayment> {
    let sections = split_payload(payload, REQUEST_LAYOUT)?;
    validate_variable_index_table(&sections, 128)?;

    let idempotency_entry = read_variable_index_entry(sections.variable_index, 0)?;
    let reference_entry = read_variable_index_entry(sections.variable_index, 1)?;
    let idempotency_key = variable_view(&sections, idempotency_entry, 32)?;
    let reference = variable_str_view(&sections, reference_entry, 128, true)?;

    if idempotency_key.as_bytes().len() != 32 {
        return Err(Error::MalformedFrame);
    }

    Ok(CapturePayment {
        merchant_id: read_u64_le(sections.required_fixed, 0)?,
        invoice_id: read_u64_le(sections.required_fixed, 8)?,
        amount_cents: read_i64_le(sections.required_fixed, 16)?,
        currency: read_u16_le(sections.required_fixed, 24)?,
        idempotency_key: idempotency_key.as_bytes().to_vec(),
        reference: reference.as_str().to_owned(),
    })
}

pub fn ack_payload(invoice_id: u64) -> Vec<u8> {
    invoice_id.to_le_bytes().to_vec()
}

pub fn decode_ack(payload: &[u8]) -> aegis_protocol::Result<u64> {
    let sections = split_payload(payload, ACK_LAYOUT)?;
    read_u64_le(sections.required_fixed, 0)
}

pub fn request_header(payload_len: usize, capability_slot: CapabilitySlot) -> HotFrameHeader {
    HotFrameHeader {
        flags: 0,
        stream_slot: STREAM,
        type_slot: REQUEST_TYPE_SLOT,
        capability_slot,
        budget_slot: BUDGET,
        seq_delta: 1,
        payload_len: payload_len as u64,
    }
}

pub fn ack_header(payload_len: usize) -> HotFrameHeader {
    HotFrameHeader {
        flags: 0,
        stream_slot: STREAM,
        type_slot: ACK_TYPE_SLOT,
        capability_slot: CAPTURE_PAYMENT_CAPABILITY,
        budget_slot: BUDGET,
        seq_delta: 1,
        payload_len: payload_len as u64,
    }
}

pub fn write_hot_packet(
    stream: &mut TcpStream,
    header: HotFrameHeader,
    payload: &[u8],
) -> io::Result<()> {
    let mut encoded_header = [0u8; MAX_HOT_HEADER_LEN];
    let header_len = header
        .encode(&mut encoded_header)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    stream.write_all(&encoded_header[..header_len])?;
    stream.write_all(payload)?;
    Ok(())
}

pub fn read_hot_packet(stream: &mut TcpStream) -> io::Result<(HotFrameHeader, Vec<u8>)> {
    let mut header_bytes = Vec::with_capacity(MAX_HOT_HEADER_LEN);
    for _ in 0..MAX_HOT_HEADER_LEN {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)?;
        header_bytes.push(byte[0]);

        match HotFrameHeader::decode(&header_bytes) {
            Ok((header, used)) => {
                let mut payload = vec![0u8; header.payload_len as usize];
                stream.read_exact(&mut payload)?;
                if used != header_bytes.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "hot header decoder left trailing bytes",
                    ));
                }
                return Ok((header, payload));
            }
            Err(Error::UnexpectedEof) => {}
            Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidData, err)),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "hot header exceeded maximum length",
    ))
}

pub fn handle_capture_payment(mut stream: TcpStream) -> io::Result<()> {
    let (header, payload) = read_hot_packet(&mut stream)?;
    let mut replay_window = ReplayWindow::<1>::new();
    let binding = CapabilityBinding::new(CAPTURE_PAYMENT_TYPE, CAPTURE_PAYMENT_CAPABILITY);
    let mut context = HotFrameValidationContext {
        budget: ResourceBudget::tiny(),
        replay_window: &mut replay_window,
        capability_binding: Some(binding),
        message_type: CAPTURE_PAYMENT_TYPE,
        absolute_sequence: header.seq_delta,
    };
    validate_hot_frame(&header, &mut context)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    let payment = decode_capture_payment(&payload)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let response_payload = ack_payload(payment.invoice_id);
    write_hot_packet(
        &mut stream,
        ack_header(response_payload.len()),
        &response_payload,
    )
}

pub fn send_capture_payment(
    address: std::net::SocketAddr,
    payment: &CapturePayment,
) -> io::Result<u64> {
    let mut stream = TcpStream::connect(address)?;
    let payload = build_capture_payment_payload(payment);
    write_hot_packet(
        &mut stream,
        request_header(payload.len(), CAPTURE_PAYMENT_CAPABILITY),
        &payload,
    )?;

    let (header, payload) = read_hot_packet(&mut stream)?;
    let mut replay_window = ReplayWindow::<1>::new();
    let mut context = HotFrameValidationContext {
        budget: ResourceBudget::tiny(),
        replay_window: &mut replay_window,
        capability_binding: None,
        message_type: MessageType::new(0x2102),
        absolute_sequence: header.seq_delta,
    };
    validate_hot_frame(&header, &mut context)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    decode_ack(&payload).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn sample_payment() -> CapturePayment {
        CapturePayment {
            merchant_id: 42,
            invoice_id: 20260523,
            amount_cents: 12_345,
            currency: 986,
            idempotency_key: vec![9; 32],
            reference: "order-123".to_owned(),
        }
    }

    #[test]
    fn client_and_server_exchange_capture_payment_over_aegis_hot_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_capture_payment(stream).unwrap();
        });

        let payment = sample_payment();
        let acknowledged_invoice = send_capture_payment(address, &payment).unwrap();

        server.join().unwrap();
        assert_eq!(acknowledged_invoice, payment.invoice_id);
    }

    #[test]
    fn replayed_hot_frame_is_rejected_before_payload_decode() {
        let payload = build_capture_payment_payload(&sample_payment());
        let header = request_header(payload.len(), CAPTURE_PAYMENT_CAPABILITY);
        let binding = CapabilityBinding::new(CAPTURE_PAYMENT_TYPE, CAPTURE_PAYMENT_CAPABILITY);
        let mut replay_window = ReplayWindow::<1>::new();

        let mut first_context = HotFrameValidationContext {
            budget: ResourceBudget::tiny(),
            replay_window: &mut replay_window,
            capability_binding: Some(binding),
            message_type: CAPTURE_PAYMENT_TYPE,
            absolute_sequence: 1,
        };
        validate_hot_frame(&header, &mut first_context).unwrap();

        let mut replay_context = HotFrameValidationContext {
            budget: ResourceBudget::tiny(),
            replay_window: &mut replay_window,
            capability_binding: Some(binding),
            message_type: CAPTURE_PAYMENT_TYPE,
            absolute_sequence: 1,
        };
        assert_eq!(
            validate_hot_frame(&header, &mut replay_context),
            Err(Error::ReplayDetected)
        );
    }

    #[test]
    fn wrong_capability_slot_is_rejected() {
        let payload = build_capture_payment_payload(&sample_payment());
        let header = request_header(payload.len(), CapabilitySlot::new(99));
        let binding = CapabilityBinding::new(CAPTURE_PAYMENT_TYPE, CAPTURE_PAYMENT_CAPABILITY);
        let mut replay_window = ReplayWindow::<1>::new();
        let mut context = HotFrameValidationContext {
            budget: ResourceBudget::tiny(),
            replay_window: &mut replay_window,
            capability_binding: Some(binding),
            message_type: CAPTURE_PAYMENT_TYPE,
            absolute_sequence: 1,
        };

        assert_eq!(
            validate_hot_frame(&header, &mut context),
            Err(Error::CapabilityDenied)
        );
    }
}
