#ifndef PACKET_BAOS_H
#define PACKET_BAOS_H

#include <epan/packet.h>
#include <epan/dissectors/packet-usb.h>
#include <epan/tvbuff-int.h>

#define FT12_START_BYTE 0x68
#define FT12_END_BYTE 0x16
#define BAOS_MAINSERVICE_CODE 0xF0
#define BAOS_START_INDEX (start_byte_index + 5)

enum SUBSERVICE_CODES
{
    GET_SERVER_ITEM_REQ_CODE        = 0x01,
    SET_SERVER_ITEM_REQ_CODE        = 0x02,
    GET_DATAPOINT_DESC_REQ_CODE     = 0x03,
    GET_DESC_STRING_REQ_CODE        = 0x04,
    GET_DATAPOINT_VALUE_REQ_CODE    = 0x05,
    SET_DATAPOINT_VALUE_REQ_CODE    = 0x06,
    GET_PARAMETER_BYTE_REQ_CODE     = 0x07,
    SET_PARAMETER_BYTE_REQ_CODE     = 0x08,
    GET_SERVER_ITEM_RES_CODE        = 0x81,
    SET_SERVER_ITEM_RES_CODE        = 0x82,
    GET_DATAPOINT_DESC_RES_CODE     = 0x83,
    GET_DESC_STRING_RES_CODE        = 0x84,
    GET_DATAPOINT_VALUE_RES_CODE    = 0x85,
    SET_DATAPOINT_VALUE_RES_CODE    = 0x86,
    GET_PARAMETER_BYTE_RES_CODE     = 0x87,
    SET_PARAMETER_BYTE_RES_CODE     = 0x88,
    DATAPOINT_VALUE_IND_CODE        = 0xC1,
    SERVER_ITEM_IND_CODE            = 0xC2
};

enum OBJECT_SERVER_RESPONSE_CODES
{
    SUCCESS                 = 0x00,
    INTERNAL_ERROR          = 0x01,
    NO_ELEMENT_FOUND        = 0x02,
    BUFFER_TOO_SMALL        = 0x03,
    ITEM_NOT_WRITABLE       = 0x04,
    SERVICE_NOT_SUPPORTED   = 0x05,
    BAD_SERVICE_PARAMETER   = 0x06,
    BAD_ID                  = 0x07,
    BAD_COMMAND_VALUE       = 0x08,
    BAD_LENGTH              = 0x09,
    MESSAGE_INCONSISTENT    = 0x0A,
    OBJECT_SERVER_BUSY      = 0x0B
};

enum CONTROL_BYTES
{
    CR_TX_ODD   = 0x73,
    CR_TX_EVEN  = 0x53,
    CR_RX_ODD   = 0xF3,
    CR_RX_EVEN  = 0xD3
};

enum BAUDRATES
{
    BAUD_UNKNOWN= 0x00,
    BAUD_19200  = 0x01,
    BAUD_115200 = 0x02
};

enum SERVER_ITEMS
{
    HARDWARE_TYPE               = 1,
    HARDWARE_VERSION            = 2,
    FIRMWARE_VERSION            = 3,
    KNX_MANUFACTURER_CODE_DEV   = 4,
    KNX_MANUFACTURER_CODE_APP   = 5,
    APPLICATION_ID_ETS          = 6,
    APPLICATION_VERSION_ETS     = 7,
    SERIAL_NUMBER               = 8,
    TIME_SINCE_RESET            = 9,
    BUS_CONNECTION_STATE        = 10,
    MAX_BUFFER_SIZE             = 11,
    LENGTH_OF_DESC_STRING       = 12,
    BAUDRATE                    = 13,
    CURRENT_BUFF_SIZE           = 14,
    PROGRAMMING_MODE            = 15,
    PROTO_VERSION_BIN           = 16,
    INDICATION_SENDING          = 17,
    PROTO_VERSION_WEBSERVICE    = 18,
    PROTO_VERSION_RESTSERVICE   = 19,
    INDIVIDUAL_ADDRESS          = 20
};

// Refer to Appendix D in the BAOS documentation to
// find out more about the available datapoint types.
enum BAOS_DPTS
{
     DPT1 = 0x01,
     DPT2 = 0x02,
     DPT3 = 0x03,
     DPT4 = 0x04,
     DPT5 = 0x05,
     DPT6 = 0x06,
     DPT7 = 0x07,
     DPT8 = 0x08,
     DPT9 = 0x09,
     DPT10 = 0x0A,
     DPT11 = 0x0B,
     DPT12 = 0x0C,
     DPT13 = 0x0D,
     DPT14 = 0x0E,
     DPT15 = 0x0F,
     DPT16 = 0x10,
     DPT17 = 0x11,
     DPT18 = 0x12,
     DPT19  = 0x13,
     DPT20  = 0x20,
     DPT232 = 0x21,
     DPT251 = 0x22,
     UNKNOWN_DPT = 0xFF
};

// Refer to Appendix C in the BAOS documentation
// to find out more about the available datapoint value types.
enum BAOS_DP_VALUE_TYPES
{
    DP_VT_1BIT = 0x00,
    DP_VT_2BIT = 0x01,
    DP_VT_3BIT = 0x02,
    DP_VT_4BIT = 0x03,
    DP_VT_5BIT = 0x04,
    DP_VT_6BIT = 0x05,
    DP_VT_7BIT = 0x06,
    DP_VT_1BYTE = 0x07,
    DP_VT_2BYTE = 0x08,
    DP_VT_3BYTE = 0x09,
    DP_VT_4BYTE = 0x0A,
    DP_VT_6BYTE = 0x0B,
    DP_VT_8BYTE = 0x0C,
    DP_VT_10BYTE = 0x0D,
    DP_VT_14BYTE = 0x0E
};

enum DP_COMMANDS
{
    NO_COMMAND                  = 0x00,
    SET_NEW_VALUE               = 0x01,
    SEND_VALUE_ON_BUS           = 0x02,
    SET_NEW_VALUE_SEND_ON_BUS   = 0x03,
    READ_NEW_VALUE_VIA_BUS      = 0x04,
    CLEAR_DP_TRANSMISSION_STATE = 0x05
};

enum DP_FILTERS
{
    GET_ALL_DP_VALUES       = 0x00,
    GET_VALID_DP_VALUES     = 0x01,
    GET_UPDATED_DP_VALUES   = 0x02
};

enum DP_STATE_VALID_FLAGS
{
    OBJECT_VAL_UNKNOWN      = 0b0,
    OBJECT_ALREADY_RECEIVED = 0b1
};

enum DP_STATE_UPDATE_FLAGS
{
    VALUE_NOT_UPDATED       = 0b0,
    VALUE_UPDATED_FROM_BUS  = 0b1
};

enum DP_STATE_READ_REQ_FLAGS
{
    SEND_WRITE_REQ  = 0b0,
    SEND_READ_REQ   = 0b1
};

enum DP_STATE_TRANSMISSION_STATES
{
    IDLE_OK             = 0b00,
    IDLE_ERROR          = 0b01,
    TRANS_IN_PROGRESS   = 0b10,
    TRANS_REQUEST       = 0b11
};

enum DP_CONFIG_FLAGS_TRANS_PRIOS
{
    SYSTEM_PRIO = 0b00,
    HIGH_PRIO   = 0b01,
    ALARM_PRIO  = 0b10,
    LOW_PRIO    = 0b11
};

// Protocol declaration
static int proto_baos;

// Header field declarations
static int hf_baos_ft12;
static int hf_baos_ft12_header;
static int hf_baos_ft12_startbyte;
static int hf_baos_ft12_lengthbyte;
static int hf_baos_ft12_controllbyte;
static int hf_baos_baos_payload;
static int hf_baos_baos_mainservice;
static int hf_baos_baos_subservice;
static int hf_baos_object_server_response;
static int hf_baos_start_server_item_id;
static int hf_baos_nr_of_server_items;
static int hf_baos_server_item_id;
static int hf_baos_server_item_length;
static int hf_baos_server_item_data;
static int hf_baos_si_hardware_type;
static int hf_baos_si_version;
static int hf_baos_si_version_major;
static int hf_baos_si_version_minor;
static int hf_baos_si_knx_man_code;
static int hf_baos_si_app_id;
static int hf_baos_si_serial_number;
static int hf_baos_si_time_since_reset;
static int hf_baos_si_server_item_status;
static int hf_baos_si_buffer_size;
static int hf_baos_si_server_item_desc_str_len;
static int hf_baos_si_baudrate;
static int hf_baos_si_knx_address;
static int hf_baos_si_knx_address_area;
static int hf_baos_si_knx_address_line;
static int hf_baos_si_knx_address_device;
static int hf_baos_start_dp_id;
static int hf_baos_nr_of_dps;
static int hf_baos_dp_id;
static int hf_baos_dp_command;
static int hf_baos_dp_state;
static int hf_baos_dp_state_valid;
static int hf_baos_dp_state_update;
static int hf_baos_dp_state_read_req;
static int hf_baos_dp_state_trans;
static int hf_baos_dp_value_type;
static int hf_baos_dp_config_flags;
static int hf_baos_dp_config_trans_prio;
static int hf_baos_dp_config_dp_comm;
static int hf_baos_dp_config_read_from_bus;
static int hf_baos_dp_config_write_from_bus;
static int hf_baos_dp_config_read_on_init;
static int hf_baos_dp_config_trans_to_bus;
static int hf_baos_dp_config_update_on_res;
static int hf_baos_dp_dpt;
static int hf_baos_dp_length;
static int hf_baos_dp_value;
static int hf_baos_dp_filter;
static int hf_baos_start_param_byte;
static int hf_baos_nr_of_param_bytes;
static int hf_baos_param_byte;
static int hf_baos_start_desc_string;
static int hf_baos_nr_of_desc_strings;
static int hf_baos_desc_string_len;
static int hf_baos_desc_string;

// ETT subtree declarations
static int ett_baos;
static int ett_ft12;
static int ett_ft12_header;
static int ett_baos_payload;
static int ett_version;
static int ett_address;
static int ett_dp_state;
static int ett_dp_config_flags;
static int ett_ft12_footer;

static const value_string vs_ft12_control_bytes[] = {
    {CR_TX_EVEN, "TX - Even"},
    {CR_TX_ODD, "TX - Odd"},
    {CR_RX_EVEN, "RX - Even"},
    {CR_RX_ODD, "RX - Odd"}
};

static const value_string vs_object_server_response[] = {
    {SUCCESS, "Success"},
    {INTERNAL_ERROR, "Internal error"},
    {NO_ELEMENT_FOUND, "No element found"},
    {BUFFER_TOO_SMALL, "Buffer is too small"},
    {ITEM_NOT_WRITABLE, "Item is not writable"},
    {SERVICE_NOT_SUPPORTED, "Service is not supported"},
    {BAD_SERVICE_PARAMETER, "Bad service parameter"},
    {BAD_ID, "Bad ID"},
    {BAD_COMMAND_VALUE, "Bad command / value"},
    {BAD_LENGTH, "Bad length"},
    {MESSAGE_INCONSISTENT, "Message inconsistent"},
    {OBJECT_SERVER_BUSY, "Object server is busy"}
};

static const value_string vs_baudrate[] = {
    {BAUD_UNKNOWN, "Unknown Baudrate"},
    {BAUD_19200, "19200"},
    {BAUD_115200, "115200"}
};

static const value_string vs_baos_dpts[] = {
    {DPT1, "DPT 1 (1 Bit, Boolean)"},
    {DPT2, "DPT 2 (2 Bit, Control)"},
    {DPT3, "DPT 3 (4 Bit, Dimming, Blinds)"},
    {DPT4, "DPT 4 (8 Bit, Character Set)"},
    {DPT5, "DPT 5 (8 Bit, Unsigned Value)"},
    {DPT6, "DPT 6 (8 Bit, Signed Value)"},
    {DPT7, "DPT 7 (2 Byte, Unsigned Value)"},
    {DPT8, "DPT 8 (2 Byte, Signed Value)"},
    {DPT9, "DPT 9 (2 Byte, Float Value)"},
    {DPT10, "DPT 10 (3 Byte, Time)"},
    {DPT11, "DPT 11 (3 Byte, Date)"},
    {DPT12, "DPT 12 (4 Byte, Unsigned Value)"},
    {DPT13, "DPT 13 (4 Byte, Signed Value)"},
    {DPT14, "DPT 14 (4 Byte, Float Value)"},
    {DPT15, "DPT 15 (4 Byte, Access)"},
    {DPT16, "DPT 16 (14 Byte, String)"},
    {DPT17, "DPT 17 (1 Byte, Scene Number)"},
    {DPT18, "DPT 18 (1 Byte, Scene Control)"},
    {DPT19, "DPT 19 (8 Byte, Date Time)"},
    {DPT20, "DPT 20 (1 Byte, HVAC Mode)"},
    {DPT232, "DPT 232 (3 Byte, Color RGB)"},
    {DPT251, "DPT 251 (6 Byte, Color RGBW)"},
    {UNKNOWN_DPT, "Unknown DPT"}
};

static const value_string vs_baos_dp_value_types[] = {
    {DP_VT_1BIT, "1 Bit"},
    {DP_VT_2BIT, "2 Bits"},
    {DP_VT_3BIT, "3 Bits"},
    {DP_VT_4BIT, "4 Bits"},
    {DP_VT_5BIT, "5 Bits"},
    {DP_VT_6BIT, "6 Bits"},
    {DP_VT_7BIT, "7 Bits"},
    {DP_VT_1BYTE, "1 Byte"},
    {DP_VT_2BYTE, "2 Bytes"},
    {DP_VT_3BYTE, "3 Bytes"},
    {DP_VT_4BYTE, "4 Bytes"},
    {DP_VT_6BYTE, "6 Bytes"},
    {DP_VT_8BYTE, "8 Bytes"},
    {DP_VT_10BYTE, "10 Bytes"},
    {DP_VT_14BYTE, "14 Bytes"}
};

static const value_string vs_dp_config_flags_tf[] = {
    {false, "Disabled"},
    {true, "Enabled"},
};

static const value_string vs_dp_config_flags_trans_prios[] = {
    {SYSTEM_PRIO, "System priority"},
    {HIGH_PRIO, "High priority"},
    {ALARM_PRIO, "Alarm priority"},
    {LOW_PRIO, "Low priority"}
};

static const true_false_string vs_server_item_status = {
    "True",
    "False"
};

// Refer to the BAOS documentation to
// find out more about the available subservices.
static const value_string vs_subservices[] = {
    {GET_SERVER_ITEM_REQ_CODE, "GetServerItem.Req"},
    {SET_SERVER_ITEM_REQ_CODE, "SetServerItem.Req"},
    {GET_DATAPOINT_DESC_REQ_CODE, "GetDatapointDescription.Req"},
    {GET_DESC_STRING_REQ_CODE, "GetDescriptionString.Req"},
    {GET_DATAPOINT_VALUE_REQ_CODE, "GetDatapointValue.Req"},
    {SET_DATAPOINT_VALUE_REQ_CODE, "SetDatapointValue.Req"},
    {GET_PARAMETER_BYTE_REQ_CODE, "GetParameterByte.Req"},
    {SET_PARAMETER_BYTE_REQ_CODE, "SetParameterByte.Req"},
    {GET_SERVER_ITEM_RES_CODE, "GetServerItem.Res"},
    {SET_SERVER_ITEM_RES_CODE, "SetServerItem.Res"},
    {GET_DATAPOINT_DESC_RES_CODE, "GetDatapointDescription.Res"},
    {GET_DESC_STRING_RES_CODE, "GetDescriptionString.Res"},
    {GET_DATAPOINT_VALUE_RES_CODE, "GetDatapointValue.Res"},
    {SET_DATAPOINT_VALUE_RES_CODE, "SetDatapointValue.Res"},
    {GET_PARAMETER_BYTE_RES_CODE, "GetParameterByte.Res"},
    {SET_PARAMETER_BYTE_RES_CODE, "SetParameterByte.Res"},
    {DATAPOINT_VALUE_IND_CODE, "DatapointValue.Ind"},
    {SERVER_ITEM_IND_CODE, "ServerItem.Ind"}
};

// Refer to Appendix A in the BAOS documentation to
// find out more about the available server items.
// For now, only the server items are present, which are
// supported in the own implementation of the BAOS protocol
static const value_string vs_server_items[] = {
    {HARDWARE_TYPE, "Hardware Type"},
    {HARDWARE_VERSION, "Hardware version"},
    {FIRMWARE_VERSION, "Firmware version"},
    {KNX_MANUFACTURER_CODE_DEV, "KNX manufacturer code DEV"},
    {KNX_MANUFACTURER_CODE_APP, "KNX manufacturer code APP"},
    {APPLICATION_ID_ETS, "Application ID (ETS)"},
    {APPLICATION_VERSION_ETS, "Application version (ETS)"},
    {SERIAL_NUMBER, "Serial number"},
    {TIME_SINCE_RESET, "Time since reset [ms]"},
    {BUS_CONNECTION_STATE, "Bus connection state"},
    {MAX_BUFFER_SIZE, "Maximum buffer size"},
    {LENGTH_OF_DESC_STRING, "Length of description string"},
    {BAUDRATE, "Baudrate"},
    {CURRENT_BUFF_SIZE, "Current buffer size"},
    {PROGRAMMING_MODE, "Programming mode"},
    {PROTO_VERSION_BIN, "Protocol Version (Binary)"},
    {INDICATION_SENDING, "Indication Sending"},
    {PROTO_VERSION_WEBSERVICE, "Protocol Version (WebService)"},
    {PROTO_VERSION_RESTSERVICE, "Protocol Version (RestService)"},
    {INDIVIDUAL_ADDRESS, "Individual Address"}
};

// Refer to the BAOS documentation to
// find out more about the available datapoint commands.
static const value_string vs_dp_commands[] = {
    {NO_COMMAND, "No command"},
    {SET_NEW_VALUE, "Set new value"},
    {SEND_VALUE_ON_BUS, "Send value on bus"},
    {SET_NEW_VALUE_SEND_ON_BUS, "Set new value and send on bus"},
    {READ_NEW_VALUE_VIA_BUS, "Read new value via bus"},
    {CLEAR_DP_TRANSMISSION_STATE, "Clear datapoint transmission state"}
};

static const value_string vs_dp_filters[] = {
    {GET_ALL_DP_VALUES, "Get all datapoint values"},
    {GET_VALID_DP_VALUES, "Get only valid datapoint values"},
    {GET_UPDATED_DP_VALUES, "Get only updated datapoint values"}
};

static const value_string vs_dp_state_valid_flags[] = {
    {OBJECT_VAL_UNKNOWN, "Object value is unknown"},
    {OBJECT_ALREADY_RECEIVED, "Object has already been received"}
};

static const value_string vs_dp_state_update_flags[] = {
    {VALUE_NOT_UPDATED, "Value is not updated"},
    {VALUE_UPDATED_FROM_BUS, "Value is updated from bus"}
};

static const value_string vs_dp_state_read_req_flags[] = {
    {SEND_WRITE_REQ, "Write request should be sent"},
    {SEND_READ_REQ, "Read request should be sent"}
};

static const value_string vs_dp_state_trans_states[] = {
    {IDLE_OK, "Idle/OK"},
    {IDLE_ERROR, "Idle/error"},
    {TRANS_IN_PROGRESS, "Transmission in progress"},
    {TRANS_REQUEST, "Transmission request"}
};

uint8_t
check_serial_baos_pattern(tvbuff_t *tvb);

void
dissect_get_server_item_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_long_server_item_telegram(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_get_datapoint_desc_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_get_desc_string_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_get_datapoint_value_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_set_datapoint_value_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_get_parameter_byte_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_set_parameter_byte_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_set_server_item_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_get_datapoint_desc_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_get_desc_string_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_get_datapoint_value_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_set_datapoint_value_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_get_parameter_byte_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_set_parameter_byte_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

static bool
dissect_baos_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

void
proto_register_baos(void);

void
proto_reg_handoff_baos(void);

#endif //PACKET_BAOS_H
