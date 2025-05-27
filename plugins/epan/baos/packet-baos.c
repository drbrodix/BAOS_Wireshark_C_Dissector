/* packet-baos.c
 *
 * Dissector for the BAOS protocol
 * By Adam Rigely <adamrigely@pm.me>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "packet-baos.h"

// Looks for FT 1.2 + BAOS payload pattern.
// Returns either the index of the FT 1.2 start byte,
// or UINT8_MAX if pattern has not been found.
uint8_t
check_serial_baos_pattern(tvbuff_t *tvb)
{
	bool is_ft12_found = false;
	bool is_baos_found = false;
	uint8_t start_byte_index = 0;

	while (start_byte_index < 5)
	{
		const uint8_t first_start_byte = tvb_get_uint8(tvb, start_byte_index);
		// First start byte found
		if (first_start_byte == FT12_START_BYTE)
		{
			const uint8_t second_start_byte = tvb_get_uint8(tvb, start_byte_index + 3);
			// Second start byte found
			if (second_start_byte == FT12_START_BYTE)
			{
				uint8_t control_byte = tvb_get_uint8(tvb, start_byte_index + 4);
				if (
					control_byte == CR_RX_ODD	||
					control_byte == CR_RX_EVEN	||
					control_byte == CR_TX_ODD	||
					control_byte == CR_TX_EVEN
					)
					is_ft12_found = true;
			}
		}
		if (is_ft12_found)
		{
			uint8_t baos_main_service_byte = tvb_get_uint8(tvb, start_byte_index + 5);
			if (baos_main_service_byte == BAOS_MAINSERVICE_CODE)
				is_baos_found = true;
			else
				is_ft12_found = false;
		}
		if (is_ft12_found && is_baos_found)
			return start_byte_index;

		start_byte_index++;
	}
	return UINT8_MAX;
}

// Checks if FT 1.2 frame is complete by looking
// for the FT 1.2 endbyte at the expected index.
// Returns true if endbyte has been found, false otherwise.
bool
check_packet_integrity(tvbuff_t *tvb, uint8_t trailer_start_index)
{
	// Check if FT 1.2 endbyte will be found at the expected index

	// Store FT 1.2 endbyte in var if it's in TVB's boundaries,
	// or assign UINT8_MAX to var if TVB is not long enough
	const uint8_t ft12_endbyte = (tvb->length >= (uint16_t)(trailer_start_index + 2)) ?
										tvb_get_uint8(tvb, trailer_start_index + 1) : UINT8_MAX;

	return (ft12_endbyte == FT12_END_BYTE);
}

// Calculates the checksum of the FT 1.2 frame based
// on algorithm documented in the BAOS documentation.
// Returns the calculated checksum.
uint32_t
calculateChecksum(tvbuff_t *tvb, uint8_t start_byte_index, uint8_t trailer_start_index)
{
	const uint8_t controllbyte_index = start_byte_index + 4;

	uint32_t sum_of_bytes = 0;
	for (uint8_t i = controllbyte_index; i < trailer_start_index; i++)
	{
		sum_of_bytes += tvb_get_uint8(tvb, i);
	}
	// Calculated checksum
	return sum_of_bytes % 256;
}

// Dissects SetServerItemReq, GetServerItemRes and ServerItemInd telegrams
void
dissect_long_server_item_telegram(tvbuff_t *tvb, proto_tree *baos_payload_tree, const uint8_t start_byte_index)
{
	// Store nr of server items in var if it's in TVB's boundaries,
	// or assign UINT8_MAX to var if TVB is not long enough
	const uint16_t nr_of_server_items = (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6)) ?
										tvb_get_uint16(tvb, BAOS_START_INDEX + 4, ENC_BIG_ENDIAN) : UINT16_MAX;

	uint16_t server_item_id_offset = BAOS_START_INDEX + 6;

	// Add ID of the starting server item
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_server_item_id,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add number of server items
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_server_items,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
	if (nr_of_server_items == 0)
	{
		// Error route
		if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 7))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_object_server_response,
								tvb,
								server_item_id_offset,
								1,
								ENC_BIG_ENDIAN
								);
		}
	}
	else
	{
		// Loop through all server items
		for (uint16_t i = 0; i < nr_of_server_items; i++)
		{
			// Setup variables for current server item iteration
			uint16_t server_item_length_offset	= server_item_id_offset + 2;
			uint16_t server_item_data_offset	= server_item_length_offset + 1;
			uint16_t server_item_id				= tvb_get_uint16(tvb, server_item_id_offset, ENC_BIG_ENDIAN);
			uint8_t server_item_data_length		= tvb->length >= server_item_length_offset ?
												tvb_get_uint8(tvb, server_item_length_offset) : UINT8_MAX;

			// Add server item ID
			if (tvb->length >= (uint16_t)(server_item_id_offset + 2))
			{
				proto_tree_add_item(
									baos_payload_tree,
									hf_baos_server_item_id,
									tvb,
									server_item_id_offset,
									2,
									ENC_BIG_ENDIAN
									);
			}
			// Add server item data length
			if (tvb->length >= (uint16_t)(server_item_length_offset + 1))
			{
				proto_tree_add_item(
									baos_payload_tree,
									hf_baos_server_item_length,
									tvb,
									server_item_length_offset,
									1,
									ENC_BIG_ENDIAN
									);
			}
			// Add server item data
			if (tvb->length >= (uint16_t)(server_item_data_offset + server_item_data_length))
			{
				switch (server_item_id)
				{
					case HARDWARE_TYPE:
						proto_tree_add_item(
									baos_payload_tree,
									hf_baos_si_hardware_type,
									tvb,
									server_item_data_offset,
									server_item_data_length,
									ENC_BIG_ENDIAN
									);
						break;
					case HARDWARE_VERSION:
					case FIRMWARE_VERSION:
					case APPLICATION_VERSION_ETS:
					case PROTO_VERSION_BIN:
					case PROTO_VERSION_WEBSERVICE:
					case PROTO_VERSION_RESTSERVICE:
						static int* const si_version_bits[] = {
							&hf_baos_si_version_major,
							&hf_baos_si_version_minor,
							NULL
						};
						proto_tree_add_bitmask(
												baos_payload_tree,
												tvb,
												server_item_data_offset,
												hf_baos_si_version,
												ett_baos_payload,
												si_version_bits,
												ENC_BIG_ENDIAN
												);
						break;
					case KNX_MANUFACTURER_CODE_DEV:
					case KNX_MANUFACTURER_CODE_APP:
						proto_tree_add_item(
									baos_payload_tree,
									hf_baos_si_knx_man_code,
									tvb,
									server_item_data_offset,
									server_item_data_length,
									ENC_BIG_ENDIAN
									);
						break;
					case APPLICATION_ID_ETS:
						proto_tree_add_item(
									baos_payload_tree,
									hf_baos_si_app_id,
									tvb,
									server_item_data_offset,
									server_item_data_length,
									ENC_BIG_ENDIAN
									);
						break;
					case SERIAL_NUMBER:
						proto_tree_add_item(
									baos_payload_tree,
									hf_baos_si_serial_number,
									tvb,
									server_item_data_offset,
									server_item_data_length,
									ENC_BIG_ENDIAN
									);
						break;
					case TIME_SINCE_RESET:
						proto_tree_add_item(
									baos_payload_tree,
									hf_baos_si_time_since_reset,
									tvb,
									server_item_data_offset,
									server_item_data_length,
									ENC_BIG_ENDIAN
									);
						break;
					case BUS_CONNECTION_STATE:
					case PROGRAMMING_MODE:
					case INDICATION_SENDING:
						proto_tree_add_item(
									baos_payload_tree,
									hf_baos_si_server_item_status,
									tvb,
									server_item_data_offset,
									server_item_data_length,
									ENC_BIG_ENDIAN
									);
						break;
					case MAX_BUFFER_SIZE:
					case CURRENT_BUFF_SIZE:
						proto_tree_add_item(
									baos_payload_tree,
									hf_baos_si_buffer_size,
									tvb,
									server_item_data_offset,
									server_item_data_length,
									ENC_BIG_ENDIAN
									);
						break;
					case LENGTH_OF_DESC_STRING:
						proto_tree_add_item(
									baos_payload_tree,
									hf_baos_si_server_item_desc_str_len,
									tvb,
									server_item_data_offset,
									server_item_data_length,
									ENC_BIG_ENDIAN
									);
						break;
					case BAUDRATE:
						proto_tree_add_item(
									baos_payload_tree,
									hf_baos_si_baudrate,
									tvb,
									server_item_data_offset,
									server_item_data_length,
									ENC_BIG_ENDIAN
									);
						break;
					case INDIVIDUAL_ADDRESS:
						static int* const si_knx_address_bits[] = {
							&hf_baos_si_knx_address_area,
							&hf_baos_si_knx_address_line,
							&hf_baos_si_knx_address_device,
							NULL
						};
						proto_tree_add_bitmask(
												baos_payload_tree,
												tvb,
												server_item_data_offset,
												hf_baos_si_knx_address,
												ett_baos_payload,
												si_knx_address_bits,
												ENC_BIG_ENDIAN
												);
						break;
					default:
						break;
				}
			}
			server_item_id_offset += server_item_data_length + 3;
			if(tvb->length < (uint16_t)(server_item_id_offset + 2))
				break;
		}
	}
}

// Dissects GetServerItemReq telegrams
void
dissect_get_server_item_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, const uint8_t start_byte_index)
{
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_server_item_id,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_server_items,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
}

// Dissects GetDatapointDescriptionReq telegrams
void
dissect_get_datapoint_desc_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index)
{
	// Add ID of the starting datapoint
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_dp_id,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add number of datapoints
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_dps,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
}

// Dissects GetDescriptionStringReq telegrams
void
dissect_get_desc_string_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index)
{
	// Add index of the starting description string
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_desc_string,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add number of description strings
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_desc_strings,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
}

// Dissects GetDatapointValueReq telegrams
void
dissect_get_datapoint_value_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index)
{
	// Add ID of the starting datapoint
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_dp_id,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add number of datapoints
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_dps,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add datapoint filter code
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 7))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_dp_filter,
							tvb,
							BAOS_START_INDEX + 6,
							1,
							ENC_BIG_ENDIAN
							);
	}
}

// Dissects SetDatapointValueReq telegrams
void
dissect_set_datapoint_value_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index)
{
	// Store nr of datapoints in var if it's in TVB's boundaries,
	// or assign UINT16_MAX to var if TVB is not long enough
	const uint16_t nr_of_dps = (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6)) ?
										tvb_get_uint16(tvb, BAOS_START_INDEX + 4, ENC_BIG_ENDIAN) : UINT16_MAX;

	uint16_t dp_id_offset = BAOS_START_INDEX + 6;

	// Add ID of the starting datapoint
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_dp_id,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add number of datapoints
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_dps,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Loop through all datapoints
	for (uint16_t i = 0; i < nr_of_dps; i++)
	{
		// Setup variables for current server item iteration
		uint16_t dp_command_offset	= dp_id_offset + 2;
		uint16_t dp_length_offset	= dp_command_offset + 1;
		uint16_t dp_value_offset	= dp_length_offset + 1;
		uint8_t dp_length			= (tvb->length >= dp_length_offset) ?
										tvb_get_uint8(tvb, dp_length_offset) : UINT8_MAX;

		// Add datapoint ID
		if (tvb->length >= (uint16_t)(dp_id_offset + 2))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_dp_id,
								tvb,
								dp_id_offset,
								2,
								ENC_BIG_ENDIAN
								);
		}
		// Add datapoint command
		if (tvb->length >= (uint16_t)(dp_command_offset + 1))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_dp_command,
								tvb,
								dp_command_offset,
								1,
								ENC_BIG_ENDIAN
								);
		}
		// Add datapoint length
		if (tvb->length >= (uint16_t)(dp_length_offset + 1))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_dp_length,
								tvb,
								dp_length_offset,
								1,
								ENC_BIG_ENDIAN
								);
		}
		// Add datapoint value
		if (tvb->length >= (uint16_t)(dp_value_offset + dp_length))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_dp_value,
								tvb,
								dp_value_offset,
								dp_length,
								ENC_BIG_ENDIAN
								);
		}
		dp_id_offset += dp_length + 4;
		if(tvb->length < (uint16_t)(dp_id_offset + 2))
			break;
	}
}

// Dissects GetParameterByteReq telegrams
void
dissect_get_parameter_byte_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index)
{
	// Add index of the starting parameter byte
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_param_byte,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add number of parameter bytes
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_param_bytes,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
}

// Dissects SetParameterByteReq telegrams
void
dissect_set_parameter_byte_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index)
{
	// Store nr of parameter bytes in var if it's in TVB's boundaries,
	// or assign UINT16_MAX to var if TVB is not long enough
	const uint16_t nr_of_param_bytes = (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6)) ?
										tvb_get_uint16(tvb, BAOS_START_INDEX + 4, ENC_BIG_ENDIAN) : UINT16_MAX;

	uint16_t param_byte_offset = BAOS_START_INDEX + 6;

	// Add index of the starting parameter byte
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_param_byte,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add number of parameter bytes
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_param_bytes,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Loop through all parameter bytes.
	// If it's a flush command telegram where start byte index
	// and nr of bytes are both 0x0000, the loop won't start
	// due to the condition in loop header being false.
	// This is optimal, since nothing else needs to be
	// dissected in the payload.
	for (uint16_t i = 0; i < nr_of_param_bytes; i++)
	{

		// Add parameter byte
		if (tvb->length >= (uint16_t)(param_byte_offset + 1))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_param_byte,
								tvb,
								param_byte_offset,
								1,
								ENC_BIG_ENDIAN
								);
		}
		param_byte_offset++;
		if(tvb->length < (uint16_t)(param_byte_offset + 1))
			break;
	}
}

// Dissects SetServerItemRes telegrams
void
dissect_set_server_item_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index)
{
	// Add ID of the starting server item
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_server_item_id,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add number of server items
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_server_items,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Object server response (Notification about success or error)
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 7))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_object_server_response,
							tvb,
							BAOS_START_INDEX + 6,
							1,
							ENC_BIG_ENDIAN
							);
	}
}

// Dissects GetDatapointDescriptionRes telegrams
void
dissect_get_datapoint_desc_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index)
{
	// Store nr of datapoints in var if it's in TVB's boundaries,
	// or assign UINT16_MAX to var if TVB is not long enough
	const uint16_t nr_of_dps = (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6)) ?
										tvb_get_uint16(tvb, BAOS_START_INDEX + 4, ENC_BIG_ENDIAN) : UINT16_MAX;

	uint16_t dp_id_offset = BAOS_START_INDEX + 6;

	// Add ID of the starting datapoint
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_dp_id,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add number of datapoints
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_dps,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add object server response if it's an error telegram
	if (!nr_of_dps && tvb->length >= (uint16_t)(BAOS_START_INDEX + 7))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_object_server_response,
							tvb,
							BAOS_START_INDEX + 6,
							1,
							ENC_BIG_ENDIAN
							);
	}
	// Loop through all datapoints
	for (uint16_t i = 0; i < nr_of_dps; i++)
	{
		// Setup variables for current server item iteration
		uint16_t dp_value_type_offset	= dp_id_offset + 2;
		uint16_t dp_config_flags_offset	= dp_value_type_offset + 1;
		uint16_t dp_dpt_offset			= dp_config_flags_offset + 1;

		// Add datapoint ID
		if (tvb->length >= (uint16_t)(dp_id_offset + 2))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_dp_id,
								tvb,
								dp_id_offset,
								2,
								ENC_BIG_ENDIAN
								);
		}
		// Add datapoint value type
		if (tvb->length >= (uint16_t)(dp_id_offset + 2))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_dp_value_type,
								tvb,
								dp_value_type_offset,
								1,
								ENC_BIG_ENDIAN
								);
		}
		// Add datapoint config flags
		if (tvb->length >= (uint16_t)(dp_config_flags_offset + 1))
		{
			static int* const config_flags_bits[] = {
				&hf_baos_dp_config_trans_prio,
				&hf_baos_dp_config_dp_comm,
				&hf_baos_dp_config_read_from_bus,
				&hf_baos_dp_config_write_from_bus,
				&hf_baos_dp_config_read_on_init,
				&hf_baos_dp_config_trans_to_bus,
				&hf_baos_dp_config_update_on_res,
				NULL
			};
			proto_tree_add_bitmask(
									baos_payload_tree,
									tvb,
									dp_config_flags_offset,
									hf_baos_dp_config_flags,
									ett_baos_payload,
									config_flags_bits,
									ENC_BIG_ENDIAN
									);
		}
		// Add datapoint type
		if (tvb->length >= (uint16_t)(dp_dpt_offset + 1))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_dp_dpt,
								tvb,
								dp_dpt_offset,
								1,
								ENC_BIG_ENDIAN
								);
		}
		dp_id_offset += 5;
		if(tvb->length < (uint16_t)(dp_id_offset + 2))
			break;
	}
}

// Dissects GetDescriptionStringRes telegrams
void
dissect_get_desc_string_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index)
{
	// Store nr of description strings in var if it's in TVB's boundaries,
	// or assign UINT16_MAX to var if TVB is not long enough
	const uint16_t nr_of_desc_strings = (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6)) ?
										tvb_get_uint16(tvb, BAOS_START_INDEX + 4, ENC_BIG_ENDIAN) : UINT16_MAX;

	uint16_t desc_string_len_offset = BAOS_START_INDEX + 6;

	// Add ID of start desc string
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_desc_string,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add number of desc strings
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_desc_strings,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add object server response if it's an error telegram
	if (!nr_of_desc_strings && tvb->length >= (uint16_t)(BAOS_START_INDEX + 7))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_object_server_response,
							tvb,
							BAOS_START_INDEX + 6,
							1,
							ENC_BIG_ENDIAN
							);
	}
	// Loop through all desc strings
	for (uint16_t i = 0; i < nr_of_desc_strings; i++)
	{
		uint16_t desc_string_offset = desc_string_len_offset + 2;

		// Store description string length in var if it's in TVB's boundaries,
		// or assign UINT16_MAX to var if TVB is not long enough
		const uint16_t desc_string_len = (tvb->length >= (uint16_t)(desc_string_len_offset + 2)) ?
											tvb_get_uint16(tvb, desc_string_len_offset, ENC_BIG_ENDIAN) : UINT16_MAX;
		// Add desc string len
		if (tvb->length >= (uint16_t)(desc_string_len_offset + 2))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_desc_string_len,
								tvb,
								desc_string_len_offset,
								2,
								ENC_BIG_ENDIAN
								);
		}
		// Add desc string
		if (tvb->length >= (uint16_t)(desc_string_offset + desc_string_len))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_desc_string,
								tvb,
								desc_string_offset,
								desc_string_len,
								ENC_BIG_ENDIAN
								);
		}
		desc_string_len_offset += desc_string_len + 2;
		if(tvb->length < (uint16_t)(desc_string_len_offset + 2))
			break;
	}
}

// Dissects GetDatapointValueRes telegrams
void
dissect_get_datapoint_value_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index)
{
	// Store nr of datapoints in var if it's in TVB's boundaries,
	// or assign UINT16_MAX to var if TVB is not long enough
	const uint16_t nr_of_dps = (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6)) ?
										tvb_get_uint16(tvb, BAOS_START_INDEX + 4, ENC_BIG_ENDIAN) : UINT16_MAX;

	uint16_t dp_id_offset = BAOS_START_INDEX + 6;

	// Add ID of the starting datapoint
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_dp_id,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add number of datapoints
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_dps,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add object server response if it's an error telegram
	if (!nr_of_dps && tvb->length >= (uint16_t)(BAOS_START_INDEX + 7))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_object_server_response,
							tvb,
							BAOS_START_INDEX + 6,
							1,
							ENC_BIG_ENDIAN
							);
	}
	// Loop through all datapoints
	for (uint16_t i = 0; i < nr_of_dps; i++)
	{
		// Setup variables for current server item iteration
		uint16_t dp_state_offset	= dp_id_offset + 2;
		uint16_t dp_length_offset	= dp_state_offset + 1;
		uint16_t dp_value_offset	= dp_length_offset + 1;
		uint8_t dp_length			= (tvb->length >= dp_length_offset) ?
										tvb_get_uint8(tvb, dp_length_offset) : UINT8_MAX;

		// Add datapoint ID
		if (tvb->length >= (uint16_t)(dp_id_offset + 2))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_dp_id,
								tvb,
								dp_id_offset,
								2,
								ENC_BIG_ENDIAN
								);
		}
		// Add datapoint state
		if (tvb->length >= (uint16_t)(dp_state_offset + 1))
		{
			static int* const dp_state_bits[] = {
				&hf_baos_dp_state_valid,
				&hf_baos_dp_state_update,
				&hf_baos_dp_state_read_req,
				&hf_baos_dp_state_trans,
				NULL
			};
			proto_tree_add_bitmask(
									baos_payload_tree,
									tvb,
									dp_state_offset,
									hf_baos_dp_state,
									ett_baos_payload,
									dp_state_bits,
									ENC_BIG_ENDIAN
									);
		}
		// Add datapoint length
		if (tvb->length >= (uint16_t)(dp_length_offset + 1))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_dp_length,
								tvb,
								dp_length_offset,
								1,
								ENC_BIG_ENDIAN
								);
		}
		// Add datapoint value
		if (tvb->length >= (uint16_t)(dp_value_offset + dp_length))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_dp_value,
								tvb,
								dp_value_offset,
								dp_length,
								ENC_BIG_ENDIAN
								);
		}
		dp_id_offset += dp_length + 4;
		if(tvb->length < (uint16_t)(dp_id_offset + 2))
			break;
	}
}

// Dissects SetDatapointValueRes telegrams
void
dissect_set_datapoint_value_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index)
{
	// Add ID of the starting datapoint
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_dp_id,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add number of datapoints
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_dps,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Object server response (Notification about success or error)
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 7))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_object_server_response,
							tvb,
							BAOS_START_INDEX + 6,
							1,
							ENC_BIG_ENDIAN
							);
	}
}

// Dissects GetParameterByteRes telegrams
void
dissect_get_parameter_byte_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index)
{
	// Store nr of parameter bytes in var if it's in TVB's boundaries,
	// or assign UINT16_MAX to var if TVB is not long enough
	const uint16_t nr_of_param_bytes = (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6)) ?
										tvb_get_uint16(tvb, BAOS_START_INDEX + 4, ENC_BIG_ENDIAN) : UINT16_MAX;

	uint16_t param_byte_offset = BAOS_START_INDEX + 6;

	// Add index of the starting parameter byte
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_param_byte,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add number of parameter bytes
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_param_bytes,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add object server response if it's an error telegram
	if (!nr_of_param_bytes && tvb->length >= (uint16_t)(BAOS_START_INDEX + 7))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_object_server_response,
							tvb,
							BAOS_START_INDEX + 6,
							1,
							ENC_BIG_ENDIAN
							);
	}
	// Loop through all parameter bytes
	for (uint16_t i = 0; i < nr_of_param_bytes; i++)
	{

		// Add parameter byte
		if (tvb->length >= (uint16_t)(param_byte_offset + 1))
		{
			proto_tree_add_item(
								baos_payload_tree,
								hf_baos_param_byte,
								tvb,
								param_byte_offset,
								1,
								ENC_BIG_ENDIAN
								);
		}
		param_byte_offset++;
		if(tvb->length < (uint16_t)(param_byte_offset + 1))
			break;
	}
}

// Dissects SetParameterByteRes telegrams
void
dissect_set_parameter_byte_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index)
{
	// Add index of the starting parameter byte
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 4))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_start_param_byte,
							tvb,
							BAOS_START_INDEX + 2,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Add number of parameter bytes
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 6))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_nr_of_param_bytes,
							tvb,
							BAOS_START_INDEX + 4,
							2,
							ENC_BIG_ENDIAN
							);
	}
	// Object server response (Notification about success or error)
	if (tvb->length >= (uint16_t)(BAOS_START_INDEX + 7))
	{
		proto_tree_add_item(
							baos_payload_tree,
							hf_baos_object_server_response,
							tvb,
							BAOS_START_INDEX + 6,
							1,
							ENC_BIG_ENDIAN
							);
	}
}

// Main function of the dissector
static bool
dissect_baos_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	// It should not be possible for a
	// serial BAOS telegram to be less than 10 bytes long.
	if (tvb->length < 10)
		return false;

	// Store index of the FT 1.2 start byte in var if FT 1.2 + BAOS pattern found,
	// or store UINT8_MAX in var if pattern has not been found.
	const uint8_t start_byte_index = check_serial_baos_pattern(tvb);

	// Returns false and ends dissection routine
	// if FT 1.2 + BAOS pattern has not been found
	if (start_byte_index == UINT8_MAX)
		return false;

	//
	// From here onwards we can assume that
	// a serial BAOS telegram has been found
	//

	// Stores length of the BAOS payload in var.
	// Checksum byte needs to be subtracted.
	const uint8_t baos_payload_len = tvb_get_uint8(tvb, start_byte_index + 1) - 1;

	// Label handled telegrams as "BAOS Telegram"
	col_set_str(pinfo->cinfo, COL_INFO, "BAOS Telegram");

	// Base BAOS tree
	proto_item *baos_ti = proto_tree_add_item(
												tree,
												proto_baos,
												tvb,
												start_byte_index,
												-1,
												ENC_NA
												);
	proto_tree *baos_tree = proto_item_add_subtree(baos_ti, ett_baos);

	// FT 1.2 frame subtree
	proto_item *ft12_ti = proto_tree_add_item(
												baos_tree,
												hf_baos_ft12,
												tvb,
												start_byte_index,
												5,
												ENC_NA
												);
	proto_tree *ft12_tree = proto_item_add_subtree(ft12_ti, ett_ft12);

	// FT 1.2 header subtree
	proto_item *ft12_header_ti = proto_tree_add_item(
													ft12_tree,
													hf_baos_ft12_header,
													tvb,
													start_byte_index,
													5,
													ENC_NA
													);
	proto_tree *ft12_header_tree = proto_item_add_subtree(ft12_header_ti, ett_ft12_header);

	// Add FT 1.2 header items
	proto_tree_add_item(
						ft12_header_tree,
						hf_baos_ft12_startbyte,
						tvb,
						start_byte_index,
						1,
						ENC_BIG_ENDIAN
						);
	proto_tree_add_item(
						ft12_header_tree,
	 					hf_baos_ft12_lengthbyte,
					 	tvb,
					 	start_byte_index + 1,
					  	1,
						ENC_BIG_ENDIAN
						);
	proto_tree_add_item(
						ft12_header_tree,
	 					hf_baos_ft12_lengthbyte,
					 	tvb,
					 	start_byte_index + 2,
					  	1,
						ENC_BIG_ENDIAN
						);
	proto_tree_add_item(
						ft12_header_tree,
	 					hf_baos_ft12_startbyte,
					 	tvb,
					 	start_byte_index + 3,
					  	1,
						ENC_BIG_ENDIAN
						);
	proto_tree_add_item(
						ft12_header_tree,
	 					hf_baos_ft12_controllbyte,
					 	tvb,
					 	start_byte_index + 4,
					  	1,
						ENC_BIG_ENDIAN
						);

	// BAOS payload subtree
	proto_item *baos_payload_ti = proto_tree_add_item(
													ft12_tree,
													hf_baos_baos_payload,
													tvb,
													BAOS_START_INDEX,
													-1,
													ENC_NA
													);
	proto_tree *baos_payload_tree = proto_item_add_subtree(baos_payload_ti, ett_baos_payload);

	// Add common BAOS payload data
	proto_tree_add_item(
						baos_payload_tree,
						hf_baos_baos_mainservice,
						tvb,
						BAOS_START_INDEX,
						1,
						ENC_BIG_ENDIAN
						);
	proto_tree_add_item(
						baos_payload_tree,
						hf_baos_baos_subservice,
						tvb,
						BAOS_START_INDEX + 1,
						1,
						ENC_BIG_ENDIAN
						);

	//
	// From here onwards, the dissection depends on the subservice
	//

	// Store BAOS subservice code in var
	const uint8_t baos_subservice_code = tvb_get_uint8(tvb, BAOS_START_INDEX + 1);

	// Call dissector function of the corresponding
	// subservice based on the found subservice code
	switch (baos_subservice_code)
	{
		case GET_SERVER_ITEM_REQ_CODE:
			dissect_get_server_item_req(tvb, baos_payload_tree, start_byte_index);
			break;
		case SET_SERVER_ITEM_REQ_CODE:
			dissect_long_server_item_telegram(tvb, baos_payload_tree, start_byte_index);
			break;
		case GET_DATAPOINT_DESC_REQ_CODE:
			dissect_get_datapoint_desc_req(tvb, baos_payload_tree, start_byte_index);
			break;
		case GET_DESC_STRING_REQ_CODE:
			dissect_get_desc_string_req(tvb, baos_payload_tree, start_byte_index);
			break;
		case GET_DATAPOINT_VALUE_REQ_CODE:
			dissect_get_datapoint_value_req(tvb, baos_payload_tree, start_byte_index);
			break;
		case SET_DATAPOINT_VALUE_REQ_CODE:
			dissect_set_datapoint_value_req(tvb, baos_payload_tree, start_byte_index);
			break;
		case GET_PARAMETER_BYTE_REQ_CODE:
			dissect_get_parameter_byte_req(tvb, baos_payload_tree, start_byte_index);
			break;
		case SET_PARAMETER_BYTE_REQ_CODE:
			dissect_set_parameter_byte_req(tvb, baos_payload_tree, start_byte_index);
			break;
		case GET_SERVER_ITEM_RES_CODE:
			dissect_long_server_item_telegram(tvb, baos_payload_tree, start_byte_index);
			break;
		case SET_SERVER_ITEM_RES_CODE:
			dissect_set_server_item_res(tvb, baos_payload_tree, start_byte_index);
			break;
		case GET_DATAPOINT_DESC_RES_CODE:
			dissect_get_datapoint_desc_res(tvb, baos_payload_tree, start_byte_index);
			break;
		case GET_DESC_STRING_RES_CODE:
			dissect_get_desc_string_res(tvb, baos_payload_tree, start_byte_index);
			break;
		case GET_DATAPOINT_VALUE_RES_CODE:
			dissect_get_datapoint_value_res(tvb, baos_payload_tree, start_byte_index);
			break;
		case SET_DATAPOINT_VALUE_RES_CODE:
			dissect_set_datapoint_value_res(tvb, baos_payload_tree, start_byte_index);
			break;
		case GET_PARAMETER_BYTE_RES_CODE:
			dissect_get_parameter_byte_res(tvb, baos_payload_tree, start_byte_index);
			break;
		case SET_PARAMETER_BYTE_RES_CODE:
			dissect_set_parameter_byte_res(tvb, baos_payload_tree, start_byte_index);
			break;
		case DATAPOINT_VALUE_IND_CODE:
			dissect_get_datapoint_value_res(tvb, baos_payload_tree, start_byte_index);
			break;
		case SERVER_ITEM_IND_CODE:
			dissect_long_server_item_telegram(tvb, baos_payload_tree, start_byte_index);
			break;
		default:
			break;
	}

	//
	// Dissection of the FT 1.2 trailer
	//

	// Calculate and store index of the start of the FT 1.2 trailer
	const uint8_t trailer_start_index = start_byte_index + 5 + baos_payload_len;

	// Check if FT 1.2 frame is complete and store result in var
	const bool is_frame_complete = check_packet_integrity(tvb, trailer_start_index);

	// Add ExpertInfo if FT 1.2 endbyte not found,
	// meaning frame is likely incomplete
	if (!is_frame_complete)
	{
		expert_add_info(pinfo, ft12_ti, &ei_ft12_incomplete_frame);
	}

	// Build FT 1.2 trailer subtree if at least
	// first byte of the trailer is in TVB
	if (tvb->length >= (uint16_t)(trailer_start_index + 1))
	{
		// FT 1.2 trailer subtree
		proto_item *ft12_trailer_ti = proto_tree_add_item(
														ft12_tree,
														hf_baos_ft12_trailer,
														tvb,
														trailer_start_index,
														2,
														ENC_NA
														);
		proto_tree *ft12_trailer_tree = proto_item_add_subtree(ft12_trailer_ti, ett_ft12_trailer);

		// Define var for checksum found in telegram
		uint32_t ft12_checksum = 0;
		// Store calculated checksum of the packet
		const uint32_t calculated_checksum = calculateChecksum(tvb, start_byte_index, trailer_start_index);

		// Add FT 1.2 checksum to tree structure
		// and store the value in "ft12_checksum"
		proto_tree_add_item_ret_uint(
							ft12_trailer_tree,
							hf_baos_ft12_checksum,
							tvb,
							trailer_start_index,
							1,
							ENC_BIG_ENDIAN,
							&ft12_checksum
							);

		// Add ExpertInfo if found checksum doesn't match
		// calculated expected checksum
		if (ft12_checksum != calculated_checksum)
		{
			expert_add_info_format(pinfo, ft12_ti, &ei_ft12_checksum_error, "Expected checksum: 0x%x Found checksum: 0x%x", calculated_checksum, ft12_checksum);
		}
		if (tvb->length >= trailer_start_index + 2u)
		{
			// Add FT 1.2 endbyte
			proto_tree_add_item(
								ft12_trailer_tree,
								hf_baos_ft12_endbyte,
								tvb,
								trailer_start_index + 1,
								1,
								ENC_BIG_ENDIAN
								);
		}
	}

	return true;
}

// Function to register protocol, HeaderFields, subtree ETTs, ExpertItems
void
proto_register_baos(void)
{
	// HeaderField definitions
	static hf_register_info hf[] = {
		{
			&hf_baos_ft12,
			{"FT 1.2",
					"baos.ft12",
					FT_PROTOCOL},
		},
		{
			&hf_baos_ft12_header,
			{"FT 1.2 Header",
					"baos.ft12.ft12_header",
					FT_PROTOCOL},
		},
		{
			&hf_baos_ft12_startbyte,
			{"FT 1.2 start byte",
					"baos.ft12.startbyte",
					FT_UINT8, BASE_HEX,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_ft12_lengthbyte,
			{"FT 1.2 length byte",
					"baos.ft12.lengthbyte",
					FT_UINT8, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_ft12_controllbyte,
			{"FT 1.2 controll byte",
					"baos.ft12.controllbyte",
					FT_UINT8, BASE_HEX,
					VALS(vs_ft12_control_bytes), 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_ft12_trailer,
			{"FT 1.2 trailer",
					"baos.ft12.ft12_trailer",
					FT_PROTOCOL},
		},
		{
			&hf_baos_ft12_checksum,
			{"FT 1.2 checksum",
					"baos.ft12.checksum",
					FT_UINT8, BASE_HEX,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_ft12_endbyte,
			{"FT 1.2 endbyte",
					"baos.ft12.endbyte",
					FT_UINT8, BASE_HEX,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_baos_payload,
			{"BAOS payload",
					"baos.payload",
					FT_PROTOCOL},
		},
		{
			&hf_baos_baos_mainservice,
			{"BAOS main service",
					"baos.mainservice",
					FT_UINT8, BASE_HEX,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_baos_subservice,
			{"BAOS subservice",
					"baos.subservice",
					FT_UINT8, BASE_HEX,
					VALS(vs_subservices), 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_object_server_response,
			{"Object server response",
					"baos.error_code",
					FT_UINT8, BASE_HEX,
					VALS(vs_object_server_response), 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_start_server_item_id,
			{"Start server item ID",
					"baos.start_server_item_id",
					FT_UINT16, BASE_DEC,
					VALS(vs_server_items), 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_nr_of_server_items,
			{"Number of server items",
					"baos.nr_of_server_items",
					FT_UINT16, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_server_item_id,
			{"Server item ID",
					"baos.server_item_id",
					FT_UINT16, BASE_DEC,
					VALS(vs_server_items), 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_server_item_length,
			{"Server item length",
					"baos.server_item_length",
					FT_UINT16, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_server_item_data,
			{"Server item data",
					"baos.server_item_data",
					FT_BYTES, SEP_SPACE,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_si_hardware_type,
			{"Hardware type",
					"baos.server_item.hardware_type",
					FT_UINT48, BASE_HEX,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_si_version,
			{"Version number",
					"baos.server_item.version",
					FT_UINT8, BASE_HEX,
					NULL, 0xFF,
					NULL, HFILL}
		},
		{
			&hf_baos_si_version_major,
			{"Major version number",
					"baos.server_item.version_major",
					FT_UINT8, BASE_DEC,
					NULL, 0xF0,
					NULL, HFILL}
		},
		{
			&hf_baos_si_version_minor,
			{"Minor version number",
					"baos.server_item.version_minor",
					FT_UINT8, BASE_DEC,
					NULL, 0x0F,
					NULL, HFILL}
		},
		{
			&hf_baos_si_knx_man_code,
			{"KNX manufacturer code",
					"baos.server_item.knx_man_code",
					FT_UINT16, BASE_HEX,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_si_app_id,
			{"Application ID",
					"baos.server_item.app_id",
					FT_UINT16, BASE_HEX,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_si_serial_number,
			{"Serial number",
					"baos.server_item.serial_number",
					FT_BYTES, SEP_SPACE,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_si_time_since_reset,
			{"Time since reset [ms]",
					"baos.server_item.app_id",
					FT_UINT32, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_si_server_item_status,
			{"Status",
					"baos.server_item.server_item_status",
					FT_BOOLEAN, BASE_HEX,
					TFS(&vs_server_item_status), 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_si_buffer_size,
			{"Buffer size [bytes]",
					"baos.server_item.buffer_size",
					FT_UINT16, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_si_server_item_desc_str_len,
			{"Length of description string",
					"baos.server_item.desc_str_len",
					FT_UINT16, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_si_baudrate,
			{"Baudrate",
					"baos.server_item.baudrate",
					FT_UINT8, BASE_HEX,
					VALS(vs_baudrate), 0x0,
					NULL, HFILL}
		},{
			&hf_baos_si_knx_address,
			{"Individual KNX address",
					"baos.server_item.knx_address",
					FT_UINT16, BASE_HEX,
					NULL, 0xFFFF,
					NULL, HFILL}
		},
		{
			&hf_baos_si_knx_address_area,
			{"Area address",
					"baos.server_item.knx_area_address",
					FT_UINT16, BASE_DEC,
					NULL, 0xF000,
					NULL, HFILL}
		},
		{
			&hf_baos_si_knx_address_line,
			{"Line address",
					"baos.server_item.knx_line_address",
					FT_UINT16, BASE_DEC,
					NULL, 0x0F00,
					NULL, HFILL}
		},
		{
			&hf_baos_si_knx_address_device,
			{"Device address",
					"baos.server_item.knx_device_address",
					FT_UINT16, BASE_DEC,
					NULL, 0x00FF,
					NULL, HFILL}
		},
		{
			&hf_baos_start_dp_id,
			{"Start datapoint ID",
					"baos.start_dp_id",
					FT_UINT16, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_nr_of_dps,
			{"Number of datapoints",
					"baos.nr_of_dps",
					FT_UINT16, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_id,
			{"Datapoint ID",
					"baos.dp_id",
					FT_UINT16, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_command,
			{"Datapoint command",
					"baos.dp_command",
					FT_UINT8, BASE_HEX,
					VALS(vs_dp_commands), 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_state,
			{"Datapoint state",
					"baos.dp_state",
					FT_UINT8, BASE_HEX,
					NULL, 0xFF,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_state_valid,
			{"Valid flag",
					"baos.dp_state.valid",
					FT_UINT8, BASE_HEX,
					VALS(vs_dp_state_valid_flags), 0b0001'0000,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_state_update,
			{"Update flag",
					"baos.dp_state.update",
					FT_UINT8, BASE_HEX,
					VALS(vs_dp_state_update_flags), 0b0000'1000,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_state_read_req,
			{"Read request flag",
					"baos.dp_state.read_req",
					FT_UINT8, BASE_HEX,
					VALS(vs_dp_state_read_req_flags), 0b0000'0100,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_state_trans,
			{"Transmission flag",
					"baos.dp_state.trans",
					FT_UINT8, BASE_HEX,
					VALS(vs_dp_state_trans_states), 0b0000'0011,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_length,
			{"Datapoint length",
					"baos.dp_length",
					FT_UINT8, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_value,
			{"Datapoint value",
					"baos.dp_value",
					FT_BYTES, SEP_SPACE,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_filter,
			{"Datapoint filter",
					"baos.dp_filter",
					FT_UINT8, BASE_HEX,
					VALS(vs_dp_filters), 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_value_type,
			{"Datapoint value type",
					"baos.dp_value_type",
					FT_UINT8, BASE_HEX,
					VALS(vs_baos_dp_value_types), 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_config_flags,
			{"Datapoint config flags",
					"baos.dp_config",
					FT_UINT8, BASE_HEX,
					NULL, 0xFF,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_config_trans_prio,
			{"Transmit priority",
					"baos.dp_config.trans_prio",
					FT_UINT8, BASE_HEX,
					VALS(vs_dp_config_flags_trans_prios), 0b0000'0011,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_config_dp_comm,
			{"Datapoint communication",
					"baos.dp_config.dp_comm",
					FT_UINT8, BASE_HEX,
					VALS(vs_dp_config_flags_tf), 0b0000'0100,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_config_read_from_bus,
			{"Read from bus",
					"baos.dp_config.read_from_bus",
					FT_UINT8, BASE_HEX,
					VALS(vs_dp_config_flags_tf), 0b0000'1000,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_config_write_from_bus,
			{"Write from bus",
					"baos.dp_config.write_from_bus",
					FT_UINT8, BASE_HEX,
					VALS(vs_dp_config_flags_tf), 0b0001'0000,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_config_read_on_init,
			{"Read on init",
					"baos.dp_config.read_on_init",
					FT_UINT8, BASE_HEX,
					VALS(vs_dp_config_flags_tf), 0b0010'0000,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_config_trans_to_bus,
			{"Transmit to bus",
					"baos.dp_config.trans_to_bus",
					FT_UINT8, BASE_HEX,
					VALS(vs_dp_config_flags_tf), 0b0100'0000,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_config_update_on_res,
			{"Update on response",
					"baos.dp_config.update_on_res",
					FT_UINT8, BASE_HEX,
					VALS(vs_dp_config_flags_tf), 0b1000'0000,
					NULL, HFILL}
		},
		{
			&hf_baos_dp_dpt,
			{"Datapoint DPT",
					"baos.dp_dpt",
					FT_UINT8, BASE_HEX,
					VALS(vs_baos_dpts), 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_start_param_byte,
			{"Start byte index",
					"baos.start_param_byte",
					FT_UINT16, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_nr_of_param_bytes,
			{"Number of bytes",
					"baos.nr_of_param_bytes",
					FT_UINT16, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_param_byte,
			{"Parameter byte",
					"baos.param_byte",
					FT_UINT8, BASE_HEX,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_start_desc_string,
			{"ID of start description string",
					"baos.start_desc_string",
					FT_UINT16, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_nr_of_desc_strings,
			{"Number of description strings",
					"baos.nr_of_desc_strings",
					FT_UINT16, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_desc_string_len,
			{"Description string length",
					"baos.desc_string_len",
					FT_UINT16, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL}
		},
		{
			&hf_baos_desc_string,
			{"Description string",
					"baos.desc_string",
					FT_STRING, BASE_STR_WSP,
					NULL, 0x0,
					NULL, HFILL}
		}
	};

	// ExpertItem definitions
	static ei_register_info ei[] = {
		{
			&ei_ft12_incomplete_frame,
			{ "baos.ft12_incomplete", PI_MALFORMED, PI_WARN,
			  "FT 1.2 likely incomplete", EXPFILL }
		},
		{
			&ei_ft12_checksum_error,
			{ "baos.checksum_error", PI_CHECKSUM, PI_ERROR,
			  "FT 1.2 checksum error", EXPFILL }
		}
	};

	// Subtree ETT definitions
	static int *ett[] = {
		&ett_baos,
		&ett_ft12,
		&ett_ft12_header,
		&ett_ft12_trailer,
		&ett_baos_payload
	};

	// Register protocol
	proto_baos = proto_register_protocol(
										"BAOS", /* name */
										"BAOS", /* short name */
										"baos" /* filter name */
										);

	// Register that the protocol has expert infos
	expert_module_t *expert_baos = expert_register_protocol(proto_baos);

	// Register HeaderFields, subtrees and ExpertItems for protocol
	proto_register_field_array(proto_baos, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_register_field_array(expert_baos, ei, array_length(ei));
}

// Register dissector as a heuristic dissector
void
proto_reg_handoff_baos(void)
{
	heur_dissector_add(
						"usb.bulk",
						dissect_baos_heur,
						"BAOS",
						"baos",
						proto_baos,
						HEURISTIC_ENABLE
						);
}