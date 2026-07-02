#include "tcp.h"
#include "utils.h"
#include "exceptions.h"
#include "raw.h"


Tcp::Tcp(uint16_t src_port, uint16_t dest_port, uint32_t sequence_number, uint32_t acknowledgement_number,
     uint8_t data_offset, uint8_t tcp_flags,uint16_t window, uint16_t checksum, uint16_t urgent_pointer)
    : _src_port(src_port),
	  _dest_port(dest_port),
	  _sequence_number(sequence_number),
	  _acknowledgement_number(acknowledgement_number),
      _data_offset(data_offset),
	  _cwr(tcp_flags & 0x80),
	  _ece(tcp_flags & 0x40),
	  _urg(tcp_flags & 0x20),
	  _ack(tcp_flags & 0x10),
	  _psh(tcp_flags & 0x08),
	  _rst(tcp_flags & 0x04),
	  _syn(tcp_flags & 0x02),
	  _fin(tcp_flags & 0x01),
	  _window(window), _checksum(checksum),
      _urgent_ptr(urgent_pointer)   
{
}

Tcp::Tcp(const Bytes &bytes)
{
	this->from_bytes(bytes);
}

void Tcp::from_bytes(const Bytes& data)
{
	if (data.size() < 20)
	{
		throw EXCEPTION(BaseException, "Invalid TCP header length");
	}

	_src_port = data.slice_int<uint16_t>(0);
	_dest_port = data.slice_int<uint16_t>(2);
	_sequence_number = data.slice_int<uint32_t>(4);
	_acknowledgement_number = data.slice_int<uint32_t>(8);
	_data_offset = data[12] >> 4; // Get left nibble

	size_t header_length = _data_offset * 4; // Data offset represents the header length in 32-bit words
	if (_data_offset < 5 || header_length > data.size())
	{
		throw EXCEPTION(BaseException, "Invalid TCP data offset\\header length");
	}

	uint8_t flags = data[13];

	// Split flags from MSB to LSB
	_cwr = flags & 0x80;
	_ece = flags & 0x40;
	_urg = flags & 0x20;
	_ack = flags & 0x10;
	_psh = flags & 0x08;
	_rst = flags & 0x04;
	_syn = flags & 0x02;
	_fin = flags & 0x01;

	_window = data.slice_int<uint16_t>(14);
	_checksum = data.slice_int<uint16_t>(16);
	_urgent_ptr = data.slice_int<uint16_t>(18);

	// options (if any) live between byte 20 and header_length are not parsed -
	// this stack never sends them and skips over them on receive
	if (data.size() > header_length)
	{
		this->_next_layer = std::make_unique<Raw>(data.slice(header_length));
	}
}


Bytes Tcp::to_bytes()
{
	Bytes result;

	result |= int_to_bytes<uint16_t>(this->_src_port);
	result |= int_to_bytes<uint16_t>(this->_dest_port);
	result |= int_to_bytes<uint32_t>(this->_sequence_number);
	result |= int_to_bytes<uint32_t>(this->_acknowledgement_number);

	uint8_t data_offset_and_reserved = _data_offset << 4; // Using reserved = 0
	result |= int_to_bytes<uint8_t>(data_offset_and_reserved);

	uint8_t flags = 
	(this->_cwr & 0x01) << 7 |
	(this->_ece & 0x01) << 6 | 
	(this->_urg & 0x01) << 5 | 
	(this->_ack & 0x01) << 4 |
	(this->_psh & 0x01) << 3 |
	(this->_rst & 0x01) << 2 |
	(this->_syn & 0x01) << 1 |
	(this->_fin & 0x01);

	result |= int_to_bytes<uint8_t>(flags);

	result |= int_to_bytes<uint16_t>(this->_window);
	result |= int_to_bytes<uint16_t>(this->_checksum);
	result |= int_to_bytes<uint16_t>(this->_urgent_ptr);

	if (this->_next_layer)
	{
		result |= this->_next_layer->to_bytes();
	}

	return result;
}

std::string Tcp::to_string() const
{
	    std::string result;

    result = this->_protocol_header_to_string("Tcp");
    result += this->_field_to_string("source port", int_to_bytes<uint16_t>(this->_src_port).to_hex());
    result += this->_field_to_string("destination port", int_to_bytes<uint16_t>(this->_dest_port).to_hex());
    result += this->_field_to_string("sequence number", int_to_bytes<uint32_t>(this->_sequence_number).to_hex());
	result += this->_field_to_string("sequence number", int_to_bytes<uint32_t>(this->_acknowledgement_number).to_hex());
	result += this->_field_to_string("data offset", byte_to_hex(this->_data_offset));

	uint8_t flags = 
	(this->_cwr & 0x01) << 7 |
	(this->_ece & 0x01) << 6 | 
	(this->_urg & 0x01) << 5 | 
	(this->_ack & 0x01) << 4 |
	(this->_psh & 0x01) << 3 |
	(this->_rst & 0x01) << 2 |
	(this->_syn & 0x01) << 1 |
	(this->_fin & 0x01);


    result += this->_field_to_string("tcp flags", "0x" + byte_to_hex(flags));
	result += this->_field_to_string("window", int_to_bytes<uint16_t>(this->_window).to_hex());
    result += this->_field_to_string("checksum", int_to_bytes<uint16_t>(this->_checksum).to_hex());
    result += this->_field_to_string("urgent pointer", int_to_bytes<uint16_t>(this->_urgent_ptr).to_hex());


    if (this->_next_layer)
    {
        result += this->_next_layer->to_string();
    }
    
    return result;
}
