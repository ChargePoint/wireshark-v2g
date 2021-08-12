v2gtp_protocol = Proto("V2G", "15118 Protocol")

-- header
sdp_version = ProtoField.uint8("sdp.ProtocolVersion", "SDP_protoVersion", base.HEX)
sdp_version_inverted = ProtoField.uint8("sdp.InvertedProtocolVersion", "SDP_invertedProtoVersion", base.HEX)
sdp_payload_type = ProtoField.uint16("sdp.PayloadType", "SDP_payloadType", base.HEX)
sdp_payload_length = ProtoField.uint32("sdp.PayloadLength", "SDP_payloadLength", base.HEX)

-- request payload
sdp_req_security = ProtoField.uint8("sdp.RequestSecurity", "SDP_Request_Security", base.HEX)
sdp_req_transport_proto = ProtoField.uint8("sdp.RequestTransportProtocol", "SDP_Request_Transport_Proto", base.HEX)

-- response payload
sdp_resp_secc_ip_addr = ProtoField.ipv6("sdp.ResponseSeccAddr", "SDP_Response_IpAddr", base.HEX)
sdp_resp_secc_port = ProtoField.uint16("sdp.ResponseSeccPort", "SDP_Response_Port", base.DEC)
sdp_resp_security = ProtoField.uint8("sdp.ResponseSecurity", "SDP_Response_Security", base.HEX)
sdp_resp_transport_proto = ProtoField.uint8("sdp.ResponseTransportProtocol", "SDP_Response_Transport_Proto", base.HEX)

-- exi payload
exi_hdr = ProtoField.uint16("sdp.ExiHdr", "SDP_EXI_HEADER", base.HEX, nil, 0xFF)
exi_msg_proto_namespace = ProtoField.string("sdp.ExiMsg", "SDP_EXI_MSG_NAMESPACE")
exi_msg_version_major = ProtoField.uint32("sdp.ExiMsgVersionMajor", "EXI_VERSION_MAJOR", base.DEC)

exi_suported_app_proto_res = ProtoField.uint8("sdp.ExiSuppAppProtoRes", "EXI_SUPP_APP_PROTO_", base.DEC, nil, 0x01)

exi_resp_code_type = ProtoField.uint8("sdp.ExiSuppAppCode", "EXI_SUPP_APP_RES_CODE", base.DEC)

v2gtp_protocol.fields = { sdp_version, sdp_version_inverted, sdp_payload_type, sdp_payload_length, sdp_req_security, sdp_req_transport_proto, sdp_resp_secc_port, sdp_resp_secc_ip_addr, sdp_resp_security, sdp_resp_transport_proto, exi_hdr, exi_msg_proto_namespace, exi_msg_version_major, exi_suported_app_proto_res, exi_resp_code_type }

function v2gtp_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end
    print(length)
    pinfo.cols.protocol = v2gtp_protocol.name
    local subtree = tree:add(v2gtp_protocol, buffer(), "V2G Protocol Data")
    
    local payload_type_name = get_sdp_payload_type(buffer(2,4):uint())
    local sdp_pay_len = buffer(4,4):uint()

    subtree:add(sdp_version, buffer(0,1))
    subtree:add(sdp_version_inverted, buffer(1,1))
    subtree:add(sdp_payload_type, buffer(2,2)):append_text("  (" .. payload_type_name .. ")")
    subtree:add(sdp_payload_length, sdp_pay_len)

    if payload_type_name == "SDP_REQUEST" then
        subtree:add(sdp_req_security, buffer(8,1)):append_text("  (" .. get_sdp_security(buffer(8,1):uint()) .. ")")
        subtree:add(sdp_req_transport_proto, buffer(9,1)):append_text("  (" .. get_sdp_transport_name(buffer(9,1):uint()) .. ")")
    end

    if payload_type_name == "SDP_RESPONSE" then

        local port = buffer(24,2):uint()

        subtree:add(sdp_resp_secc_ip_addr, buffer(8,16))
        subtree:add(sdp_resp_secc_port, port)
        subtree:add(sdp_resp_security, buffer(26,1)):append_text("  (" .. get_sdp_security(buffer(26,1):uint()) .. ")")
        subtree:add(sdp_resp_transport_proto, buffer(27,1)):append_text("  (" .. get_sdp_transport_name(buffer(27,1):uint()) .. ")")
        
        -- we don't know what port we're using at the start, add our
        -- dissector to the supported tls dissector (if you have session
        -- keys you can decrypt packets with this)
        DissectorTable.get("tls.port"):add(port, v2gtp_protocol)

    end

    if payload_type_name == "EXI_ENCODED" then
        -- skip 0x80 (first byte)

        subtree:add(exi_hdr, buffer(9,2))

        -- we're a supportedAppProtocol{Req,Res}
        local bitval = buffer(9,2):bitfield(0, 1)
        subtree:add(exi_suported_app_proto_res, bitval)
        print('bit', bitval)
end

function get_sdp_payload_type(type)
    local type_name = "Unknown"

    if type == 0x90000000 then type_name = "SDP_REQUEST"
    elseif type == 0x90010000 then type_name = "SDP_RESPONSE"
    elseif type == 0x80010000 then type_name = "EXI_ENCODED"
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

local udp_port = DissectorTable.get("udp.port")
udp_port:add(15118, v2gtp_protocol)
