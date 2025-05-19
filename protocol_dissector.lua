ftpb = Proto("ftpb","Beta FTP")

packettypes = {"Connection", "Success", "Error", "Registration", "Authentication", "Download file"}

local ftpb_hdr_payload_length = ProtoField.uint32("ftpb.pl_len", "Payload length", base.DEC)
local ftpb_hdr_connection_id = ProtoField.guid("ftpb.hdr.conn_id", "Connection ID", base.NONE)
local ftpb_hdr_msg_type = ProtoField.uint8("ftpb.hdr.msg_type", "Type", base.HEX, packettypes)
local ftpb_hdr_flags = ProtoField.uint8("ftpb.hdr.flags", "Flags", base.BIN)

local ftpb_payload = ProtoField.bytes("ftpb.payload", "Payload")

ftpb.fields = {
  ftpb_hdr_payload_length,
  ftpb_hdr_connection_id,
  ftpb_hdr_msg_type,
  ftpb_hdr_flags,
  ftpb_payload
}

function ftpb.dissector (buf, pinfo, tree)
	if buf:len() == 0 then return end
	pinfo.cols.protocol = ftpb.name
	
	subtree = tree:add(ftpb, buf(0))
	
	subtree:add_le(ftpb_hdr_payload_length, buf(0,4))
	subtree:add(ftpb_hdr_connection_id, buf(4,16))
	subtree:add(ftpb_hdr_msg_type, buf(20,1))
	subtree:add(ftpb_hdr_flags, buf(21,1))
	subtree:add(ftpb_payload, buf(22,buf(0,4):le_uint()))
	
	local type_str = packettypes[buf(20,1):uint()]
	if type_str == nil then type_str = "Unknown" end
	pinfo.cols.info = "Type: " .. type_str
end

local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(33333, ftpb)


