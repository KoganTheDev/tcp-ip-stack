#include "tcp.h"
#include "utils.h"
#include "exceptions.h"
#include "raw.h"

#include <utility>


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

Tcp::Tcp(Bytes bytes)
{
	// move the buffer straight into the field we keep for the checksum, then
	// parse out of it - no second copy of the segment
	this->_received_bytes = std::move(bytes);
	this->_parse();
}

void Tcp::from_bytes(const Bytes& data)
{
	// virtual-interface entry point - copies the bytes in, unlike the Tcp(Bytes)
	// constructor the receive hot path uses, then parses the same way
	this->_received_bytes = data;
	this->_parse();
}

void Tcp::_parse()
{
	const Bytes& data = this->_received_bytes;

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
		else if (kind == 4 && length == 2)
		{
			_has_sack_permitted_option = true;
		}
		else if (kind == 5 && length >= 10 && ((length - 2) % 8) == 0)
		{
			// Each block is two 32-bit sequence numbers: left edge, right edge.
			size_t block_count = static_cast<size_t>(length - 2) / 8;
			for (size_t b = 0; b < block_count; b++)
			{
				size_t at = i + 2 + b * 8;
				SackBlock block;
				block.start = data.slice_int<uint32_t>(at);
				block.end = data.slice_int<uint32_t>(at + 4);
				_sack_blocks.push_back(block);
			}
		}
		else if (kind == 8 && length == 10)
		{
			_has_timestamp_option = true;
			_timestamp_value = data.slice_int<uint32_t>(i + 2);
			_timestamp_echo = data.slice_int<uint32_t>(i + 6);
		}
		else if (kind == 3 && length == 3)
		{
			_has_window_scale_option = true;
			// Clamp rather than reject: RFC 7323 SS2.3 says a shift count above
			// 14 should be treated as 14 (with the peer's behaviour logged as
			// suspect), not that the segment is invalid. Clamping here rather
			// than at each use site is deliberate - this is the boundary where
			// untrusted bytes become a value the rest of the stack trusts, and
			// there are four separate places that use it as a shift count.
			uint8_t shift = data[i + 2];
			_window_scale_option = shift > MAX_WINDOW_SCALE ? MAX_WINDOW_SCALE : shift;
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
	if (this->_has_sack_permitted_option)
	{
		options.append_int<uint8_t>(4); // kind: SACK-permitted
		options.append_int<uint8_t>(2);
	}
	if (!this->_sack_blocks.empty())
	{
		// Two NOPs so the sequence numbers themselves land 32-bit aligned,
		// which is what every implementation does and what makes them cheap to
		// read on the far side.
		options.append_int<uint8_t>(1); // NOP
		options.append_int<uint8_t>(1); // NOP
		options.append_int<uint8_t>(5); // kind: SACK
		options.append_int<uint8_t>(static_cast<uint8_t>(2 + this->_sack_blocks.size() * 8));
		for (const SackBlock& block : this->_sack_blocks)
		{
			options.append_int<uint32_t>(block.start);
			options.append_int<uint32_t>(block.end);
		}
	}
	if (this->_has_timestamp_option)
	{
		// Two NOPs first. The option is 10 bytes, so padding it to a 4-byte
		// boundary is unavoidable; putting the padding in front leaves the two
		// 32-bit values themselves aligned, which is what every implementation
		// does and what makes them cheap to read.
		options.append_int<uint8_t>(1); // NOP
		options.append_int<uint8_t>(1); // NOP
		options.append_int<uint8_t>(8); // kind: timestamps
		options.append_int<uint8_t>(10);
		options.append_int<uint32_t>(this->_timestamp_value);
		options.append_int<uint32_t>(this->_timestamp_echo);
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
