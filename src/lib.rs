#[derive(Debug)]
pub enum BufferError {
    EndOfBuffer,
}

pub type Result<T> = std::result::Result<T, BufferError>;

pub struct DnsPacketBuffer<'input> {
    buf: &'input [u8],
    pos: usize,
}

impl<'input> DnsPacketBuffer<'input> {
    pub fn new(input: &'input [u8]) -> Self {
        DnsPacketBuffer { buf: input, pos: 0 }
    }

    fn get_u8(&mut self) -> Result<u8> {
        if self.pos >= self.buf.len() {
            Err(BufferError::EndOfBuffer)
        } else {
            let value = self.buf[self.pos];
            self.pos += 1;
            Ok(value)
        }
    }

    pub fn get_u16(&mut self) -> Result<u16> {
        let high = self.get_u8()? as u16;
        let low = self.get_u8()? as u16;
        Ok(high << 8 | low)
    }

    #[allow(dead_code)]
    fn skip(&mut self, n: usize) -> Result<()> {
        if self.pos + n > self.buf.len() {
            Err(BufferError::EndOfBuffer)
        } else {
            self.pos += n;
            Ok(())
        }
    }

    #[allow(dead_code)]
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct DnsHeader {
    packet_id: u16,

    query_response_indicator: bool, // QR
    opcode: u8,                     // 4 bits
    authoritative_answer: bool,     // AA
    truncation: bool,               // TC
    recursion_desired: bool,        // RD

    recursion_available: bool, // RA
    reserved: u8,              // Z (must be 0)
    response_code: u8,         // RCODE (4 bits)

    question_count: u16,          // QDCOUNT
    answer_record_count: u16,     // ANCOUNT
    authority_record_count: u16,  // NSCOUNT
    additional_record_count: u16, // ARCOUNT
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QType {
    A = 1,
    CNAME = 5,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QClass {
    IN = 1,
    CS = 2,
}

pub struct Question {
    qname: String,
    qtype: QType,
    qclass: QClass,
}

struct Message {
    header: DnsHeader,
    question: Question,
}

pub struct MessageWriter {
    message: Message,
}

impl MessageWriter {
    pub fn new(header: DnsHeader, question: Question) -> MessageWriter {
        MessageWriter {
            message: Message { header, question },
        }
    }

    pub fn write(&self, buf: &mut [u8]) -> Result<usize> {
        fn write_u16(buf: &mut [u8], off: usize, val: u16) -> Result<()> {
            if off + 2 > buf.len() {
                return Err(BufferError::EndOfBuffer);
            }
            let bytes = val.to_be_bytes();
            buf[off] = bytes[0];
            buf[off + 1] = bytes[1];
            Ok(())
        }

        let mut offset = 0usize;

        if buf.len() < 12 {
            return Err(BufferError::EndOfBuffer);
        }

        write_u16(buf, offset, self.message.header.packet_id)?;
        offset += 2;

        let mut flags: u16 = 0;
        if self.message.header.query_response_indicator {
            flags |= 1 << 15;
        }
        flags |= ((self.message.header.opcode as u16) & 0xF) << 11;
        if self.message.header.authoritative_answer {
            flags |= 1 << 10;
        }
        if self.message.header.truncation {
            flags |= 1 << 9;
        }
        if self.message.header.recursion_desired {
            flags |= 1 << 8;
        }
        if self.message.header.recursion_available {
            flags |= 1 << 7;
        }
        flags |= ((self.message.header.reserved as u16) & 0x7) << 4;
        flags |= (self.message.header.response_code as u16) & 0xF;

        write_u16(buf, offset, flags)?;
        offset += 2;

        write_u16(buf, offset, self.message.header.question_count)?;
        offset += 2;
        write_u16(buf, offset, self.message.header.answer_record_count)?;
        offset += 2;
        write_u16(buf, offset, self.message.header.authority_record_count)?;
        offset += 2;
        write_u16(buf, offset, self.message.header.additional_record_count)?;
        offset += 2;

        let written_qname = self.message.question.encode_qname(&mut buf[offset..])?;
        offset += written_qname;

        let qtype_u16 = match self.message.question.qtype {
            QType::A => 1u16,
            QType::CNAME => 5u16,
        };
        write_u16(buf, offset, qtype_u16)?;
        offset += 2;

        let qclass_u16 = match self.message.question.qclass {
            QClass::IN => 1u16,
            QClass::CS => 2u16,
        };
        write_u16(buf, offset, qclass_u16)?;
        offset += 2;

        Ok(offset)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 512];
        let len = self.write(&mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }
}

impl Question {
    pub fn new(name: &str) -> Question {
        Question {
            qname: name.to_string(),
            qtype: QType::A,
            qclass: QClass::IN,
        }
    }

    pub fn with_type_class(name: &str, qtype: QType, qclass: QClass) -> Question {
        Question {
            qname: name.to_string(),
            qtype,
            qclass,
        }
    }

    pub fn encode_qname(&self, buf: &mut [u8]) -> Result<usize> {
        let mut offset = 0usize;

        for label in self.qname.split('.') {
            let len = label.len();
            if len == 0 {
                continue;
            }
            if offset + 1 + len > buf.len() {
                return Err(BufferError::EndOfBuffer);
            }
            buf[offset] = len as u8;
            offset += 1;
            buf[offset..offset + len].copy_from_slice(label.as_bytes());
            offset += len;
        }

        if offset >= buf.len() {
            return Err(BufferError::EndOfBuffer);
        }
        buf[offset] = 0;
        offset += 1;

        Ok(offset)
    }
}

impl DnsHeader {
    pub fn parse(parser: &mut DnsPacketBuffer) -> Result<DnsHeader> {
        let packet_id = parser.get_u16()?;

        let flags = parser.get_u16()?;
        let query_response_indicator = (flags >> 15) & 1 == 1;
        let opcode = ((flags >> 11) & 0xF) as u8;
        let authoritative_answer = (flags >> 10) & 1 == 1;
        let truncation = (flags >> 9) & 1 == 1;
        let recursion_desired = (flags >> 8) & 1 == 1;
        let recursion_available = (flags >> 7) & 1 == 1;
        let reserved = ((flags >> 4) & 0x7) as u8; // bits 4–6 (should be 0)
        let response_code = (flags & 0xF) as u8;

        let question_count = parser.get_u16()?;
        let answer_record_count = parser.get_u16()?;
        let authority_record_count = parser.get_u16()?;
        let additional_record_count = parser.get_u16()?;

        Ok(DnsHeader {
            packet_id,
            query_response_indicator,
            opcode,
            authoritative_answer,
            truncation,
            recursion_desired,
            recursion_available,
            reserved,
            response_code,
            question_count,
            answer_record_count,
            authority_record_count,
            additional_record_count,
        })
    }

    pub fn response_with_id(id: u16) -> DnsHeader {
        DnsHeader {
            packet_id: id,
            query_response_indicator: true,
            opcode: 0,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: false,
            recursion_available: false,
            reserved: 0,
            response_code: 0,
            question_count: 1,
            answer_record_count: 0,
            authority_record_count: 0,
            additional_record_count: 0,
        }
    }
}
