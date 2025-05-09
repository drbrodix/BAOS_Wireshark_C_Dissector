#ifndef PACKET_BAOS_H
#define PACKET_BAOS_H

#include "config.h"
#include <epan/packet.h>
#include <epan/tvbuff-int.h>
#include <epan/dissectors/packet-usb.h>

#define FT12_START_BYTE 0x68
#define FT12_END_BYTE 0x16
#define BAOS_MAINSERVICE_CODE 0xF0
#define BAOS_START_INDEX start_byte_index + 5

enum CONTROL_BYTES
{
    CR_TX_ODD   = 0x73,
    CR_TX_EVEN  = 0x53,
    CR_RX_ODD   = 0xF3,
    CR_RX_EVEN  = 0xD3
};

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

/*local function dissectGetServerItemRes(packetBuffer, packetBufferLen, dataFirstIndex, baosTree)

    -- Variables for readability
    local bufferBytesArray <const>  = packetBuffer:bytes()
    -- Get nrOfServerItems if the bytes are accessible or assign nil to the variable
    local nrOfServerItems = (packetBufferLen >= (dataFirstIndex + 4)) and bufferBytesArray:int(dataFirstIndex + 2, 2) or nil
    local isErrorRes                = nrOfServerItems == 0

    -- Index offsets used while looping through all server items
    local serverItemIdOffset        = dataFirstIndex + 4
    local serverItemLengthOffset    = serverItemIdOffset + 2
    local serverItemDataOffset      = serverItemLengthOffset + 1

    -- Add ID of the starting server item
    if packetBufferLen >= (dataFirstIndex + 2) then
        baosTree:add
                    (
                        f_startServerItemId,
                        packetBuffer(dataFirstIndex, 2)
                    )
    else return false end
    -- Add number of server items
    if packetBufferLen >= (dataFirstIndex + 4) then
        baosTree:add
                    (
                        f_nrOfServerItems,
                        packetBuffer(dataFirstIndex + 2, 2)
                    )
    else return false end

    if isErrorRes then
        -- Add object server response (what kind of error)
        if packetBufferLen >= (serverItemIdOffset + 1) then
            baosTree:add
                        (
                            f_objectServerResponse,
                            packetBuffer(serverItemIdOffset, 1)
                        )
        else return false end
    else
        -- Get serverItemLength and serverItemId if the bytes are accessible or assign nil to the variables
        local serverItemLength  = (packetBufferLen >= (serverItemLengthOffset + 1)) and bufferBytesArray:int(serverItemLengthOffset, 1) or nil
        local serverItemId      = (packetBufferLen >= (serverItemIdOffset + 2)) and bufferBytesArray:int(serverItemIdOffset, 2) or nil

        -- Base serverItemProtoField-Add function
        local function addBasicProtoField (protoField)
            if packetBufferLen >= (serverItemDataOffset + serverItemLength) then
                baosTree:add
                            (
                                protoField,
                                packetBuffer(serverItemDataOffset, serverItemLength)
                            )
            else return false end
        end

        -- Version serverItemProtoField-Add function
        local function addVersionProtoField ()
            if packetBufferLen >= (serverItemDataOffset + serverItemLength) then
                local versionTree = baosTree:add
                                                (
                                                    f_version,
                                                    packetBuffer(serverItemDataOffset, serverItemLength)
                                                )
                versionTree:add
                                (
                                    f_versionMajor,
                                    packetBuffer(serverItemDataOffset, serverItemLength)
                                )
                versionTree:add
                                (
                                    f_versionMinor,
                                    packetBuffer(serverItemDataOffset, serverItemLength)
                                )
            else return false end
        end

        -- KNX-Address serverItemProtoField-Add function
        local function addKNXAddressProtoField ()

            if packetBufferLen >= (serverItemDataOffset + serverItemLength) then
                local KNXAddressTree = baosTree:add
                                                    (
                                                        f_KNXAddress,
                                                        packetBuffer(serverItemDataOffset, serverItemLength)
                                                    )
                KNXAddressTree:add
                                    (
                                        f_KNXAreaAddress,
                                        packetBuffer(serverItemDataOffset, 1)
                                    )
                KNXAddressTree:add
                                    (
                                        f_KNXLineAddress,
                                        packetBuffer(serverItemDataOffset, 1)
                                    )
                KNXAddressTree:add
                                    (
                                        f_KNXDeviceAddress,
                                        packetBuffer(serverItemDataOffset + 1, 1)
                                    )
            else return false end
        end

        -- Custom dissector functions for the server items
        local serverItemFuncs =
                                {
                                    -- Hardware type
                                    [1] = function ()
                                        addBasicProtoField(f_hardwareType)
                                    end,
                                    -- Hardware version
                                    [2] = function ()
                                        addVersionProtoField()
                                    end,
                                    -- Firmware version
                                    [3] = function ()
                                        addVersionProtoField()
                                    end,
                                    -- KNX manufacturer code DEV
                                    [4] = function ()
                                        addBasicProtoField(f_KNXManCode)
                                    end,
                                    -- KNX manufacturer code APP
                                    [5] = function ()
                                        addBasicProtoField(f_KNXManCode)
                                    end,
                                    -- Application ID (ETS)
                                    [6] = function ()
                                        addBasicProtoField(f_appID)
                                    end,
                                    -- Application version (ETS)
                                    [7] = function ()
                                        addVersionProtoField()
                                    end,
                                    -- Serial number
                                    [8] = function ()
                                        addBasicProtoField(f_serialNumber)
                                    end,
                                    -- Time since reset [ms]
                                    [9] = function ()
                                        addBasicProtoField(f_timeSinceReset)
                                    end,
                                    -- Bus connection state
                                    [10] = function ()
                                        addBasicProtoField(f_serverItemStatus)
                                    end,
                                    -- Maximum buffer size
                                    [11] = function ()
                                        addBasicProtoField(f_bufferSize)
                                    end,
                                    -- Length of description string
                                    [12] = function ()
                                        addBasicProtoField(f_serverItemDescStrLen)
                                    end,
                                    -- Baudrate
                                    [13] = function ()
                                        addBasicProtoField(f_baudrate)
                                    end,
                                    -- Current buffer size
                                    [14] = function ()
                                        addBasicProtoField(f_bufferSize)
                                    end,
                                    -- Programming mode
                                    [15] = function ()
                                        addBasicProtoField(f_serverItemStatus)
                                    end,
                                    -- Protocol Version (Binary)
                                    [16] = function ()
                                        addVersionProtoField()
                                    end,
                                    -- Indication Sending
                                    [17] = function ()
                                        addBasicProtoField(f_serverItemStatus)
                                    end,
                                    -- Protocol Version (WebService)
                                    [18] = function ()
                                        addVersionProtoField()
                                    end,
                                    -- Protocol Version (RestService)
                                    [19] = function ()
                                        addVersionProtoField()
                                    end,
                                    -- Individual Address
                                    [20] = function ()
                                        addKNXAddressProtoField()
                                    end,
                                }

        -- Loop through all server items
        for i = 1, nrOfServerItems, 1 do
            -- Add server item ID
            if packetBufferLen >= (serverItemIdOffset + 2) then
                baosTree:add
                            (
                                f_serverItemId,
                                packetBuffer(serverItemIdOffset, 2)
                            )
            else return false end
            -- Add server item data length
            if packetBufferLen >= (serverItemLengthOffset + 1) then
                baosTree:add
                            (
                                f_serverItemLength,
                                packetBuffer(serverItemLengthOffset, 1)
                            )
            else return false end
            -- Add server item data
            serverItemFuncs[serverItemId]()

            -- Set offset to start byte of the next server item
            if packetBufferLen >= (serverItemIdOffset + 3 + serverItemLength) then
                serverItemIdOffset = serverItemIdOffset + 3 + serverItemLength
            else break end
        end
    end
end*/

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
static int hf_baos_start_server_item_id;
static int hf_baos_nr_of_server_items;
static int hf_baos_server_item_id;
static int hf_baos_server_item_length;
static int hf_baos_server_item_data;

static const value_string vs_ft12_control_bytes[] = {
    {CR_TX_EVEN, "TX - Even"},
    {CR_TX_ODD, "TX - Odd"},
    {CR_RX_EVEN, "RX - Even"},
    {CR_RX_ODD, "RX - Odd"}
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
    {1, "Hardware Type"},
    {2, "Hardware version"},
    {3, "Firmware version"},
    {4, "KNX manufacturer code DEV"},
    {5, "KNX manufacturer code APP"},
    {6, "Application ID (ETS)"},
    {7, "Application version (ETS)"},
    {8, "Serial number"},
    {9, "Time since reset [ms]"},
    {10, "Bus connection state"},
    {11, "Maximum buffer size"},
    {12, "Length of description string"},
    {13, "Baudrate"},
    {14, "Current buffer size"},
    {15, "Programming mode"},
    {16, "Protocol Version (Binary)"},
    {17, "Indication Sending"},
    {18, "Protocol Version (WebService)"},
    {19, "Protocol Version (RestService)"},
    {20, "Individual Address"}
};

// ETT subtree declarations
static int ett_baos;
static int ett_ft12;
static int ett_ft12_header;
static int ett_baos_payload;
static int ett_ft12_footer;

uint8_t
check_serial_baos_pattern(tvbuff_t *tvb);

void
dissect_get_server_item_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_set_server_item_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_get_server_item_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

void
dissect_set_server_item_res(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

static bool
dissect_baos_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

void
proto_register_baos(void);

void
proto_reg_handoff_baos(void);

#endif //PACKET_BAOS_H
