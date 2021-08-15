-- Docs: https://www.w3.org/TR/2014/REC-exi-20140211/#header

exi_protocol = Proto("exi", "Efficient XML Interchange Format")

local EXI_F = {
    cookie = ProtoField.string("exi.cookie", "EXI Cookie", base.ASCII), -- 4 bytes
    dbits = ProtoField.uint8("exi.dbits", "Distinguished bits", base.HEX, nil, 0xC0),
    presence = ProtoField.bool("exi.presence", "Presence Bit"),
    version = ProtoField.uint8("exi.version", "Version bits", base.DEC),
    -- options
    -- padding
}

exi_protocol.fields = EXI_F

-- https://www.w3.org/TR/2014/REC-exi-20140211/#key-version
function get_exi_version(buffer, tree, offset)
    local version = buffer(offset,1):bitfield(3,1) -- first bit is "version"
    local bitoffset = 4
    local n = buffer(offset,1):bitfield(bitoffset,4) -- read 4 bits
    version = version + n
    local next_version = version
    while (next_version > 14) do
        bitoffset = bitoffset + 4
        next_version = buffer(offset,1):bitfield(bitoffset,4)
        version = version + next_version
    end
    local display_version = "Version " .. (tonumber(version) == 0 and 1 or tonumber(version))
    if buffer(offset,1):bitfield(3,1) == 1 then
        display_version = "Preview " .. display_version
    else
        display_version = "Final " .. display_version
    end
    tree:add(EXI_F["version"], version, display_version)
end

function exi_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = exi_protocol.name

    local subtree = tree:add(exi_protocol,buffer(0))
    local offset = 0

    -- add (optional) cookie if any
    if buffer:len() >= 4 and buffer(offset,4):string() == "$EXI" then
        subtree:add(EXI_F["cookie"], buffer(offset,4), "  (" .. cookie .. ")")
        offset = offset + 4
    end

    -- distinguished bits
    subtree:add(EXI_F["dbits"], buffer(offset,1))

    -- presence bit
    options_available = buffer(offset,1):bitfield(2,1)
    subtree:add(EXI_F["presence"], options_available)

    -- version
    get_exi_version(buffer, subtree, offset)
    offset = offset + 1

    -- options (depends on )
    -- https://www.w3.org/TR/2014/REC-exi-20140211/#key-options
    if options_available == 1 then
        -- TODO process options
        print("TODO: process options")
        -- padding (depends on options above)
    end

    -- dump the entire EXI message, ignoring our offset so a HEX stream
    -- export can be read by another EXI decoding tool
    if buffer:len() > offset then
        Dissector.get("data"):call(buffer(0):tvb(), pinfo, subtree)
    end
end
