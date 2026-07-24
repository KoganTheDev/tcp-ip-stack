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

	// keep the exact bytes for checksum verification - see get_received_bytes()
	this->_received_bytes = data;

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

	// Options (RFC 793 SS3.1): a sequence of kind/[length/data] TLVs between
	// byte 20 and header_length. Only MSS (kind 2) and window scale (kind 3)
	// are understood - anything else is skipped via its own length byte,
	// which is what makes this forward-compatible instead of a parse error.
	_has_mss_option = false;
	_has_window_scale_option = false;
	size_t i = 20;
	while (i < header_length)
	{
		uint8_t kind = data[i];
		if (kind == 0) // End of Option List
		{
			break;
		}
		if (kind == 1) // No-Operation (padding) - no length byte
		{
			i += 1;
			continue;
		}

		if (i + 1 >= header_length)
		{
			break; // truncated option with no length byte - stop, don't read out of bounds
		}
		uint8_t length = data[i + 1];
		if (length < 2 || i + length > header_length)
		{
			break; // malformed length - stop rather than read past the header
		}

		if (kind == 2 && length == 4)
		{
			_has_mss_option = true;
			_mss_option = data.slice_int<uint16_t>(i + 2);
		}
		else if (kind == 3 && length == 3)
		{
			_has_window_scale_option = true;
			_window_scale_option = data[i + 2];
		}

		i += length;
	}

	if (data.size() > header_length)
	{
		this->_next_layer = std::make_unique<Raw>(data.slice(header_length));
	}
}

Bytes Tcp::_options_to_bytes()
{
	Bytes options;
	if (this->_has_mss_option)
	{
		options.append_int<uint8_t>(2); // kind: MSS
		options.append_int<uint8_t>(4); // length (bytes, including kind+length)
		options.append_int<uint16_t>(this->_mss_option);
	}
	if (this->_has_window_scale_option)
	{
		options.append_int<uint8_t>(3); // kind: window scale
		options.append_int<uint8_t>(3);
		options.append_int<uint8_t>(this->_window_scale_option);
	}
	while (options.size() % 4 != 0)
	{
		options.append_int<uint8_t>(1); // NOP padding - data_offset counts whole 32-bit words
	}
	return options;
}


Bytes Tcp::to_bytes()
{
	// data_offset depends on however many option bytes (if any) are set -
	// recomputed here rather than trusted from construction, since options
	// are attached after construction via set_mss_option()/
	// set_window_scale_option() (mirrors how set_checksum() is also a
	// post-construction mutator).
	Bytes options = this->_options_to_bytes();
	this->_data_offset = static_cast<uint8_t>(5 + options.size() / 4);

	Bytes result;
	result.reserve(20 + options.size()); // avoids reallocating as fields are appended

	result.append_int<uint16_t>(this->_src_port);
	result.append_int<uint16_t>(this->_dest_port);
	result.append_int<uint32_t>(this->_sequence_number);
	result.append_int<uint32_t>(this->_acknowledgement_number);

	uint8_t data_offset_and_reserved = _data_offset << 4; // Using reserved = 0
	result.append_int<uint8_t>(data_offset_and_reserved);

	uint8_t flags =
	(this->_cwr & 0x01) << 7 |
	(this->_ece & 0x01) << 6 |
	(this->_urg & 0x01) << 5 |
	(this->_ack & 0x01) << 4 |
	(this->_psh & 0x01) << 3 |
	(this->_rst & 0x01) << 2 |
	(this->_syn & 0x01) << 1 |
	(this->_fin & 0x01);

	result.append_int<uint8_t>(flags);

	result.append_int<uint16_t>(this->_window);
	result.append_int<uint16_t>(this->_checksum);
	result.append_int<uint16_t>(this->_urgent_ptr);
	result |= options;

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
