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
#define CR_TX_ODD	0x73
#define CR_TX_EVEN	0x53
#define CR_RX_ODD	0xF3
#define CR_RX_EVEN	0xD3
#define GET_SERVER_ITEM_REQ_CODE 0x01
#define SET_SERVER_ITEM_REQ_CODE 0x02
#define GET_DATAPOINT_DESC_REQ_CODE 0x03
#define GET_DESC_STRING_REQ_CODE 0x04
#define GET_DATAPOINT_VALUE_REQ_CODE 0x05
#define SET_DATAPOINT_VALUE_REQ_CODE 0x06
#define GET_PARAMETER_BYTE_REQ_CODE 0x07
#define SET_PARAMETER_BYTE_REQ_CODE 0x08
#define GET_SERVER_ITEM_RES_CODE 0x81
#define SET_SERVER_ITEM_RES_CODE 0x82
#define GET_DATAPOINT_DESC_RES_CODE 0x83
#define GET_DESC_STRING_RES_CODE 0x84
#define GET_DATAPOINT_VALUE_RES_CODE 0x85
#define SET_DATAPOINT_VALUE_RES_CODE 0x86
#define GET_PARAMETER_BYTE_RES_CODE 0x87
#define SET_PARAMETER_BYTE_RES_CODE 0x88
#define DATAPOINT_VALUE_IND_CODE 0xC1
#define SERVER_ITEM_IND_CODE 0xC2

static int proto_baos;

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

static const value_string subservices[] = {
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

static int ett_baos;
static int ett_ft12;
static int ett_ft12_header;
static int ett_baos_payload;
static int ett_ft12_footer;

uint8_t
check_serial_baos_pattern(tvbuff_t *tvb);

void
dissect_get_server_item_req(tvbuff_t *tvb, proto_tree *baos_payload_tree, uint8_t start_byte_index);

static bool
dissect_baos_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

void
proto_register_baos(void);

void
proto_reg_handoff_baos(void);

#endif //PACKET_BAOS_H
