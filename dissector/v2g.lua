--
-- Copyright (c) 2021 ChargePoint, Inc.
-- All rights reserved.
--
-- See LICENSE file
--

v2gtp_protocol = Proto("V2GTP", "Vehicle to Grid Transfer Protocol")

-- V2G TP protocol
local V2GTP_HEADER_LENGTH = 8

-- SDP (SECC Discovery Protocol)
local SDP = {
    -- header (8 bytes)
    version = ProtoField.uint8("sdp.ProtocolVersion", "SDP Protocol Version", base.HEX),
    version_inverted = ProtoField.uint8("sdp.InvertedProtocolVersion", "SDP Inverted Protocol Version", base.HEX),
    payload_type = ProtoField.uint16("sdp.PayloadType", "SDP Payload Type", base.HEX),
    payload_length = ProtoField.uint32("sdp.PayloadLength", "SDP Payload Length", base.HEX),

    -- request payload (2 bytes only for normal SDP)
    request_security = ProtoField.uint8("sdp.RequestSecurity", "SDP Request Security", base.HEX),
    request_transport_proto = ProtoField.uint8("sdp.RequestTransportProtocol", "SDP Request Transport Protocol", base.HEX),
    request_emsp_ids = ProtoField.string("sdp.RequestEMSPIDs", "EMSP IDs"),

    -- response payload
    response_secc_ip_addr = ProtoField.ipv6("sdp.ResponseSeccAddr", "SDP Response IP Address", base.HEX),
    response_secc_port = ProtoField.uint16("sdp.ResponseSeccPort", "SDP Response Port", base.DEC),
    response_security = ProtoField.uint8("sdp.ResponseSecurity", "SDP Response Security", base.HEX),
    response_transport_proto = ProtoField.uint8("sdp.ResponseTransportProtocol", "SDP Response Transport Protocol", base.HEX),
    response_emsp_ids = ProtoField.string("sdp.ResponseEMSPIDs", "EMSP IDs"),
}

local V2GTP_EXIDISSECTOR_DEFAULT = 0
local V2GTP_EXIDISSECTOR_DIN = 1
local V2GTP_EXIDISSECTOR_ISO1 = 2
local V2GTP_EXIDISSECTOR_ISO2 = 3

local v2gtp_exidissector_tab =  {
    { 1, "Default", V2GTP_EXIDISSECTOR_DEFAULT },
    { 2, "DIN", V2GTP_EXIDISSECTOR_DIN },
    { 3, "ISO1", V2GTP_EXIDISSECTOR_ISO1 },
    { 4, "ISO2", V2GTP_EXIDISSECTOR_ISO2 },
}

v2gtp_protocol.prefs.exidissector = Pref.enum(
    "EXI Dissector", -- label
    V2GTP_EXIDISSECTOR_DEFAULT, -- default value
    "Dissector to use for EXI", -- description
    v2gtp_exidissector_tab, -- enum table
    false -- show as combo box
)

v2gtp_protocol.fields = SDP

function set_contains(set, key)
    return set[key] ~= nil
end

function get_sdp_version(value)
    local version = "RESERVED"
    if value == 0x01 or bit32.bxor(value, 0xFF) == 0x01 then version = "V2GTP Version 1" end

    return version
end

function get_sdp_payload_type(type)
    local type_name = "UNKNOWN"

    local types = {
    [0x9000] = "SDP REQUEST",
    [0x9001] = "SDP RESPONSE",
    [0x9004] = "SDP EMSP REQUEST",
    [0x9005] = "SDP EMSP RESPONSE",
    [0x8001] = "EXI ENCODED",
    [0x9002] = "RESERVED",
    [0X9003] = "RESERVED",
    }

    if set_contains(types, type) then return types[type] end

    if type < 0x8000 then type_name = "RESERVED"
    elseif type >= 0x8001 and type <= 0x8FFF then type_name = "RESERVED"
    elseif type >= 0x9006 and type <= 0x9FFF then type_name = "RESERVED"
    elseif type >= 0xA000 and type <= 0xFFFF then type_name = "MFG SPECIFIC"
    end

    return type_name
end

function get_sdp_security(req)
    local security = "TLS: NO"

    if req == 0x00 then security = "TLS: YES" end
    return security
end

function get_sdp_transport_name(req)
    local transport = "Unknown"

    if req == 0x00 then transport = "TCP" end
    return transport
end

function append_paren_text(text)
    return "  (" .. text .. ")"
end

function get_v2gtp_length(buffer, pinfo, offset)
    return V2GTP_HEADER_LENGTH + buffer(offset + 4,4):uint()
end

function dissect_v2gtp(buffer, pinfo, tree)
    local payload_type_name = get_sdp_payload_type(buffer(2,2):uint())
    local sdp_pay_len = buffer(4,4):uint()

    local subtree = tree:add(v2gtp_protocol, buffer(), "V2G Transfer Protocol")
    subtree:add(SDP["version"], buffer(0,1)):append_text(
        append_paren_text(
            get_sdp_version(buffer(0,1):uint())
        )
    )
    subtree:add(SDP["version_inverted"], buffer(1,1)):append_text(
        append_paren_text(
            get_sdp_version(buffer(0,1):uint())
        )
    )
    subtree:add(SDP["payload_type"], buffer(2,2)):append_text(
        append_paren_text(
            payload_type_name
        )
    )
    subtree:add(SDP["payload_length"], buffer(4,4), sdp_pay_len):append_text(
        append_paren_text(
            "Payload Length: " .. sdp_pay_len
    )
)

    if payload_type_name == "SDP REQUEST" then
        local security_display = get_sdp_security(buffer(8,1):uint()) == "TLS: YES" and " (Secure)" or " (Non-Secure)"
        pinfo.cols.info:set('SDP Request' .. security_display)
        local subtree = tree:add(v2gtp_protocol, buffer(), "SDP Request")
        subtree:add(SDP["request_security"], buffer(8,1)):append_text("  (" .. get_sdp_security(buffer(8,1):uint()) .. ")")
        subtree:add(SDP["request_transport_proto"], buffer(9,1)):append_text("  (" .. get_sdp_transport_name(buffer(9,1):uint()) .. ")")
    elseif payload_type_name == "SDP RESPONSE" then
        local security_display = get_sdp_security(buffer(26,1):uint()) == "TLS: YES" and " (Secure)" or " (Non-Secure)"
        pinfo.cols.info:set('SDP Response' .. security_display)
        local subtree = tree:add(v2gtp_protocol, buffer(), "SDP Response")
        local port = buffer(24,2):uint()
        local security = buffer(26,1):uint()

        subtree:add(SDP["response_secc_ip_addr"], buffer(8,16))
        subtree:add(SDP["response_secc_port"], buffer(24,2))
        subtree:add(SDP["response_security"], buffer(26,1)):append_text("  (" .. get_sdp_security(buffer(26,1):uint()) .. ")")
        subtree:add(SDP["response_transport_proto"], buffer(27,1)):append_text("  (" .. get_sdp_transport_name(buffer(27,1):uint()) .. ")")
        
        -- we don't know what port we're using at the start, add our
        -- dissector to the supported tls dissector (if you have session
        -- keys you can decrypt packets with this)
        if buffer(27,1):uint() == 0 then
            -- TCP
            if security == 0x10 then
                -- NO TLS
                DissectorTable.get("tcp.port"):add(port, v2gtp_protocol)
            elseif security == 0x00 then
                -- TLS
                DissectorTable.get("tls.port"):add(port, v2gtp_protocol)
            end
        end
    elseif payload_type_name == "SDP EMSP REQUEST" then
        pinfo.cols.info:set('SDP with EMSP Request')
        local subtree = tree:add(v2gtp_protocol, buffer(), "SDP EMSP Request")
        subtree:add(SDP["request_security"], buffer(8,1)):append_text("  (" .. get_sdp_security(buffer(8,1):uint()) .. ")")
        subtree:add(SDP["request_transport_proto"], buffer(9,1)):append_text("  (" .. get_sdp_transport_name(buffer(9,1):uint()) .. ")")

        local emsp_ids = buffer(10):string()
        subtree:add(SDP["request_emsp_ids"], buffer(10, buffer:len() - 10)):set_text("EMSP IDs: " .. emsp_ids)

    elseif payload_type_name == "SDP EMSP RESPONSE" then
        pinfo.cols.info:set('SDP with EMSP Response')
        local subtree = tree:add(v2gtp_protocol, buffer(), "SDP EMSP Response")
        subtree:add(SDP["response_secc_ip_addr"], buffer(8,16))
        subtree:add(SDP["response_secc_port"], buffer(24,2))
        subtree:add(SDP["response_security"], buffer(26,1)):append_text("  (" .. get_sdp_security(buffer(26,1):uint()) .. ")")
        subtree:add(SDP["response_transport_proto"], buffer(27,1)):append_text("  (" .. get_sdp_transport_name(buffer(27,1):uint()) .. ")")

        local emsp_ids = buffer(28):string()
        subtree:add(SDP["response_emsp_ids"], buffer(28, buffer:len() - 28)):set_text("EMSP IDs: " .. emsp_ids)


    elseif payload_type_name == "EXI ENCODED" then
        if v2gtp_protocol.prefs.exidissector == V2GTP_EXIDISSECTOR_DIN then
            Dissector.get("v2gdin"):call(buffer(V2GTP_HEADER_LENGTH):tvb(), pinfo, tree)
        elseif v2gtp_protocol.prefs.exidissector == V2GTP_EXIDISSECTOR_ISO1 then
            Dissector.get("v2giso1"):call(buffer(V2GTP_HEADER_LENGTH):tvb(), pinfo, tree)
        elseif v2gtp_protocol.prefs.exidissector == V2GTP_EXIDISSECTOR_ISO2 then
            Dissector.get("v2giso2"):call(buffer(V2GTP_HEADER_LENGTH):tvb(), pinfo, tree)
        else
            Dissector.get("v2gexi"):call(buffer(V2GTP_HEADER_LENGTH):tvb(), pinfo, tree)
        end
    end
end


function v2gtp_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end
    pinfo.cols.protocol = v2gtp_protocol.name

    if pinfo.port_type == 3 then -- UDP
        dissect_v2gtp(buffer, pinfo, tree)
    else
        dissect_tcp_pdus(buffer, tree, V2GTP_HEADER_LENGTH, get_v2gtp_length, dissect_v2gtp)
    end
end

-- we need this so our other lua files get loaded
function v2gtp_protocol.init()
    -- Add V2GTP to the dissector table
    DissectorTable.get("udp.port"):add(15118, v2gtp_protocol)
    DissectorTable.get("tcp.port"):add(15118, v2gtp_protocol)
    DissectorTable.get("tls.port"):add(15118, v2gtp_protocol)
end
