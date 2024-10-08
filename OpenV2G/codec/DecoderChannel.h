/*
 * Copyright (C) 2007-2015 Siemens AG
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*******************************************************************
 *
 * @author Daniel.Peintner.EXT@siemens.com
 * @version 0.9.3 
 * @contact Joerg.Heuer@siemens.com
 *
 * <p>Code generated by EXIdizer</p>
 * <p>Schema: V2G_CI_MsgDef.xsd</p>
 *
 *
 ********************************************************************/



/**
 * \file 	DecoderChannel.h
 * \brief 	EXI Decoder Channel
 *
 */

#ifndef DECODER_CHANNEL_H
#define DECODER_CHANNEL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "EXIOptions.h"
#include "EXITypes.h"

/**
 * \brief 		Decode byte value
 *
 * \param       stream   		Input Stream
 * \param       b		   		byte (out)
 * \return                  	Error-Code <> 0
 *
 */
int decode(bitstream_t* stream, uint8_t* b);


/**
 * \brief 		Decode boolean
 *
 * 				Decode a single boolean value. The value false is
 * 				represented by 0, and the value true is represented by 1.
 *
 * \param       stream   		Input Stream
 * \param       b		   		boolean (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeBoolean(bitstream_t* stream, int* b);


/**
 * \brief 		Decode n-bit unsigned integer
 *
 * 				Decodes and returns an n-bit unsigned integer.
 *
 * \param       stream   		Input Stream
 * \param       nbits		   	Number of bits
 * \param       uint32		   	Value (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeNBitUnsignedInteger(bitstream_t* stream, uint16_t nbits, uint32_t* uint32);


/**
 * \brief 		Decode unsigned integer
 *
 * 				Decode an arbitrary precision non negative integer using
 * 				a sequence of octets. The most significant bit of the last
 * 				octet is set to zero to indicate sequence termination.
 * 				Only seven bits per octet are used to store the integer's value.
 *
 * \param       stream   		Input Stream
 * \param       iv		   		Unsigned Integer Value (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeUnsignedInteger(bitstream_t* stream, exi_integer_t* iv);


/**
 * \brief 		Decode unsigned integer
 *
 * 				Decode an arbitrary precision non negative integer using
 * 				a sequence of octets. The most significant bit of the last
 * 				octet is set to zero to indicate sequence termination.
 * 				Only seven bits per octet are used to store the integer's value.
 *
 * \param       stream   		Input Stream
 * \param       uint16		   	Unsigned Integer Value 16 bits (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeUnsignedInteger16(bitstream_t* stream, uint16_t* uint16);


/**
 * \brief 		Decode unsigned integer
 *
 * 				Decode an arbitrary precision non negative integer using
 * 				a sequence of octets. The most significant bit of the last
 * 				octet is set to zero to indicate sequence termination.
 * 				Only seven bits per octet are used to store the integer's value.
 *
 * \param       stream   		Input Stream
 * \param       uint32		   	Unsigned Integer Value 32 bits (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeUnsignedInteger32(bitstream_t* stream, uint32_t* uint32);


/**
 * \brief 		Decode unsigned integer
 *
 * 				Decode an arbitrary precision non negative integer using
 * 				a sequence of octets. The most significant bit of the last
 * 				octet is set to zero to indicate sequence termination.
 * 				Only seven bits per octet are used to store the integer's value.
 *
 * \param       stream   		Input Stream
 * \param       uint64		   	Unsigned Integer Value 64 bits (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeUnsignedInteger64(bitstream_t* stream, uint64_t* uint64);


/**
 * \brief 		Decode integer
 *
 * 				Decode an arbitrary precision integer using a sign bit
 * 				followed by a sequence of octets. The most significant bit
 * 				of the last octet is set to zero to indicate sequence termination.
 * 				Only seven bits per octet are used to store the integer's value.
 *
 * \param       stream   		Input Stream
 * \param       iv		   		Integer Value 64 bits (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeInteger(bitstream_t* stream, exi_integer_t* iv);


/**
 * \brief 		Decode integer
 *
 * 				Decode an arbitrary precision integer using a sign bit
 * 				followed by a sequence of octets. The most significant bit
 * 				of the last octet is set to zero to indicate sequence termination.
 * 				Only seven bits per octet are used to store the integer's value.
 *
 * \param       stream   		Input Stream
 * \param       int16		   	Integer Value 16 bits (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeInteger16(bitstream_t* stream, int16_t* int16);


/**
 * \brief 		Decode integer
 *
 * 				Decode an arbitrary precision integer using a sign bit
 * 				followed by a sequence of octets. The most significant bit
 * 				of the last octet is set to zero to indicate sequence termination.
 * 				Only seven bits per octet are used to store the integer's value.
 *
 * \param       stream   		Input Stream
 * \param       int32		   	Integer Value 32 bits (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeInteger32(bitstream_t* stream, int32_t* int32);


/**
 * \brief 		Decode integer
 *
 * 				Decode an arbitrary precision integer using a sign bit
 * 				followed by a sequence of octets. The most significant bit
 * 				of the last octet is set to zero to indicate sequence termination.
 * 				Only seven bits per octet are used to store the integer's value.
 *
 * \param       stream   		Input Stream
 * \param       int64		   	Integer Value 64 bits (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeInteger64(bitstream_t* stream, int64_t* int64);


/**
 * \brief 		Decode float
 *
 * 				Decode a Float datatype as two consecutive Integers. The
 * 				first Integer represents the mantissa of the floating point
 * 				number and the second Integer represents the base-10 exponent
 * 				of the floating point number.
 *
 * \param       stream   		Input Stream
 * \param       f			   	Float Value (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeFloat(bitstream_t* stream, exi_float_me_t* f);


/**
 * \brief 		Decode decimal
 *
 * 				Decode a decimal represented as a Boolean sign followed by two
 * 				Unsigned Integers. A sign value of zero (0) is used to represent
 * 				positive Decimal values and a sign value of one (1) is used to
 * 				represent negative Decimal values The first Integer represents
 * 				the integral portion of the Decimal value. The second positive
 * 				integer represents the fractional portion of the decimal with
 * 				the digits in reverse order to preserve leading zeros.
 *
 * \param       stream   		Input Stream
 * \param       d			   	Decimal Value (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeDecimal(bitstream_t* stream, exi_decimal_t* d);


/**
 * \brief 		Decode String (no length prefix)
 *
 * 				Decode a sequence of characters for a given length.
 *
 * \param       stream   		Input Stream
 * \param       len			   	Characters length
 * \param       s			   	String Value (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeStringOnly(bitstream_t* stream, uint16_t len, exi_string_t* s);


/**
 * \brief 		Decode String
 *
 * 				Decode a length prefixed sequence of characters.
 *
 * \param       stream   		Input Stream
 * \param       s			   	String Value (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeString(bitstream_t* stream, exi_string_t* s);



/**
 * \brief 		Decode String value
 *
 * 				Decode a length prefixed sequence of characters in the sense of string tables.
 * 				length == 0: local value partition hit.
 * 				length == 1: global value partition hit.
 * 				length > 1: string literal is encoded as a String with the length incremented by two
 *
 * \param       stream   		Input Stream
 * \param       state   		Codec state
 * \param       qnameID   		Qualified Name ID
 * \param       s			   	String Value (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeStringValue(bitstream_t* stream, exi_state_t* state, uint16_t qnameID, exi_string_value_t* s);


/**
 * \brief 		Decode Restricted characters set string value
 *
 * \param       stream   		Input Stream
 * \param       state   		Codec state
 * \param       qnameID   		Qualified Name ID
 * \param       rcs		   		Restricted character set
 * \param       s			   	String Value (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeRCSStringValue(bitstream_t* stream, exi_state_t* state, uint16_t qnameID, exi_rcs_t* rcs, exi_string_value_t* s);


/**
 * \brief 		Decode characters
 *
 * 				Decode a sequence of characters according to a given length.
 *
 * \param       stream   		Input Stream
 * \param       len		   		Length
 * \param       chars   		Characters (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeCharacters(bitstream_t* stream, uint16_t len, exi_string_character_t* chars);


/**
 * \brief 		Decode restricted character set characters
 *
 * 				Decode a sequence of characters according to a given length and rcs code-length, size and set.
 *
 * \param       stream   		Input Stream
 * \param       len		   		Length
 * \param       chars   		Characters (out)
 * \param       rcsCodeLength   RCS code-length
 * \param       rcsCodeLength   RCS size
 * \param       rcsCodeLength   RCS set
 * \return                  	Error-Code <> 0
 *
 */
int decodeRCSCharacters(bitstream_t* stream, uint16_t len, exi_string_character_t* chars, uint16_t rcsCodeLength, uint16_t rcsSize, const exi_string_character_t rcsSet[]);



/**
 * \brief 		Decode Binary
 *
 * 				Decode a binary value as a length-prefixed sequence of octets.
 *
 * \param       stream   		Input Stream
 * \param       bytes   		Bytes (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeBinary(bitstream_t* stream, exi_bytes_t* bytes);

/**
 * \brief 		Decode Binary data
 *
 * 				Decode a sequence of octets.
 *
 * \param       stream   		Input Stream
 * \param       len		   		Length
 * \param       data	   		Bytes (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeBytes(bitstream_t* stream, uint16_t len, uint8_t* data);

/**
 * \brief 		Decode DateTime
 *
 * 				Decode Date-Time as sequence of values representing the
 * 				individual components of the Date-Time.
 *
 * \param       stream   		Input Stream
 * \param       type   			Datetime type
 * \param       datetime   		Datetime (out)
 * \return                  	Error-Code <> 0
 *
 */
int decodeDateTime(bitstream_t* stream, exi_datetime_type_t type, exi_datetime_t* datetime);


#ifdef __cplusplus
}
#endif

#endif
