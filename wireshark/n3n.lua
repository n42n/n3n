-- (C) 2019 - ntop.org and contributors
-- (C) 2024 Hamish Coleman

n3n = Proto("n3n", "n3n VPN Protocol")

-- #############################################

PKT_TYPE_PING               = 0
PKT_TYPE_REGISTER           = 1
PKT_TYPE_DEREGISTER         = 2
PKT_TYPE_PACKET             = 3
PKT_TYPE_REGISTER_ACK       = 4
PKT_TYPE_REGISTER_SUPER     = 5
PKT_TYPE_UNREGISTER_SUPER   = 6
PKT_TYPE_REGISTER_SUPER_ACK = 7
PKT_TYPE_REGISTER_SUPER_NAK = 8
PKT_TYPE_FEDERATION         = 9
PKT_TYPE_PEER_INFO          = 10
PKT_TYPE_QUERY_PEER         = 11
PKT_TYPE_RE_REGISTER_SUPER  = 12

PKT_TRANSFORM_NULL      = 1
PKT_TRANSFORM_TWOFISH   = 2
PKT_TRANSFORM_AESCBC    = 3

PKT_COMPRESSION_NONE    = 1
PKT_COMPRESSION_LZO     = 2
PKT_COMPRESSION_ZSTD    = 3

FLAG_FROM_SUPERNODE   = 0x0020
FLAG_SOCKET           = 0x0040

SOCKET_FLAG_AF_INET  = 0x0000
-- SOCKET_FLAG_?     = 0x2000
SOCKET_FLAG_TCP      = 0x4000
SOCKET_FLAG_AF_INET6 = 0x8000

-- #############################################

version = ProtoField.uint8("n3n.version", "version", base.DEC)
ttl = ProtoField.uint8("n3n.ttl", "ttl", base.DEC)

packet_type_mask = 0x001f
pkt_type_2_str = {
  [PKT_TYPE_PING] = "ping",
  [PKT_TYPE_REGISTER] = "register",
  [PKT_TYPE_DEREGISTER] = "deregister",
  [PKT_TYPE_PACKET] = "packet",
  [PKT_TYPE_REGISTER_ACK] = "register_ack",
  [PKT_TYPE_REGISTER_SUPER] = "register_super",
  [PKT_TYPE_REGISTER_SUPER_ACK] = "register_super_ack",
  [PKT_TYPE_REGISTER_SUPER_NAK] = "register_super_nak",
  [PKT_TYPE_FEDERATION] = "federation",
  [PKT_TYPE_PEER_INFO] = "peer_info",
  [PKT_TYPE_QUERY_PEER] = "query_peer",
}
packet_type = ProtoField.uint8("n3n.packet_type", "packetType", base.HEX, pkt_type_2_str, packet_type_mask)

flags_mask = 0xffe0
flags = ProtoField.uint16("n3n.flags", "Flags", base.HEX, nil, flags_mask)
from_supernode_flag = ProtoField.uint16("n3n.flags.from_supernode", "from_supernode", base.BOOLEAN, nil, FLAG_FROM_SUPERNODE)
socket_flag = ProtoField.uint16("n3n.flags.socket", "socket", base.BOOLEAN, nil, FLAG_SOCKET)
community = ProtoField.string("n3n.community", "Community", base.ASCII)

-- #############################################

src_mac = ProtoField.ether("n3n.src_mac", "Source")
dst_mac = ProtoField.ether("n3n.dst_mac", "Destination")
socket_info = ProtoField.none("n3n.socket", "Socket Info")
socket_family = ProtoField.uint16("n3n.socket.family", "Family", base.HEX, {
  [0] = "AF_INET",
})
socket_port = ProtoField.uint16("n3n.socket.port", "Port")
socket_ipv4 = ProtoField.ipv4("n3n.socket.ipv4", "IPv4")
socket_ipv6 = ProtoField.ipv6("n3n.socket.ipv6", "IPv6")

-- #############################################

peer_info_field = ProtoField.none("n3n.peer_info", "PeerInfo")
peer_info_flags = ProtoField.uint16("n3n.peer_info.flags", "Flags")
peer_info_mac = ProtoField.ether("n3n.peer_info.query_mac", "Query")

query_peer_field = ProtoField.none("n3n.query_peer", "QueryPeer")
aflags = ProtoField.uint16("n3n.query_peer.aflags", "aflags")

-- #############################################



packet_field = ProtoField.none("n3n.packet", "Packet")
packet_compression = ProtoField.uint8("n3n.packet.compression", "Compression", base.HEX, {
  [PKT_COMPRESSION_NONE] = "None",
  [PKT_COMPRESSION_LZO] = "LZO",
  [PKT_COMPRESSION_ZSTD] = "zstd",
})
packet_transform = ProtoField.uint8("n3n.packet.transform", "Transform", base.HEX, {
  [PKT_TRANSFORM_NULL] = "Plaintext",
  [PKT_TRANSFORM_TWOFISH] = "TwoFish",
  [PKT_TRANSFORM_AESCBC] = "AES CBC",
})
packet_payload = ProtoField.bytes("n3n.packet.payload", "Payload")

-- #############################################

register_field = ProtoField.none("n3n.register", "Register")
register_cookie = ProtoField.uint32("n3n.register.cookie", "Cookie", base.HEX)
register_ipv4 = ProtoField.ipv4("n3n.register.ipv4", "IPv4")
register_ipv4_masklen = ProtoField.uint8("n3n.register.masklen", "masklen")
register_desc = ProtoField.string("n3n.register.desc", "Description", base.ASCII)

register_ack_field = ProtoField.none("n3n.register_ack", "RegisterACK")
register_ack_cookie = ProtoField.uint32("n3n.register_ack.cookie", "Cookie", base.HEX)

register_super_field = ProtoField.none("n3n.register_super", "RegisterSuper")
register_super_cookie = ProtoField.uint32("n3n.register_super.cookie", "Cookie", base.HEX)
register_super_auth_schema = ProtoField.uint16("n3n.register_super.auth.schema", "AuthSchema", base.HEX)
register_super_auth_size = ProtoField.uint16("n3n.register_super.auth.token_size", "AuthTokenSize", base.HEX)
register_super_auth_data = ProtoField.bytes("n3n.register_super.auth.data", "AuthData")
register_super_key_time = ProtoField.absolute_time("n3n.register_super.key_time", "key_time")

register_super_ack_field = ProtoField.none("n3n.register_super_ack", "RegisterSuperACK")
register_super_ack_cookie = ProtoField.uint32("n3n.register_super_ack.cookie", "Cookie", base.HEX)
register_super_ack_lifetime = ProtoField.uint16("n3n.register_super_ack.lifetime", "Registration Lifetime", base.DEC)
register_super_ack_num_sn = ProtoField.uint8("n3n.register_super_ack.num_sn", "Num Supernodes", base.DEC)

supernode_info = ProtoField.none("n3n.supernode", "Supernode Info")

-- #############################################

n3n.fields = {
  version, ttl, packet_type,
  flags, from_supernode_flag, socket_flag,
  community,

  -- Generic
  src_mac, dst_mac,
  socket_info, socket_family, socket_port, socket_ipv4, socket_ipv6,

  -- PKT_TYPE_REGISTER
  register_field, register_cookie,
  register_ipv4, register_ipv4_masklen, register_desc,
  -- PKT_TYPE_PACKET
  packet_field, packet_compression, packet_transform, packet_payload,
  -- PKT_TYPE_REGISTER_ACK
  register_ack_field, register_ack_cookie,
  -- PKT_TYPE_REGISTER_SUPER
  register_super_field, register_super_cookie,
  register_super_auth_schema, register_super_auth_size,
  register_super_auth_data,
  register_super_key_time,
  -- PKT_TYPE_REGISTER_SUPER_ACK
  register_super_ack_field, register_super_ack_cookie,
  register_super_ack_lifetime, register_super_ack_num_sn,
  supernode_info,
  -- PKT_TYPE_PEER_INFO
  peer_info_field, peer_info_flags, peer_info_mac,
  -- PKT_TYPE_QUERY_PEER
  query_peer_field,
  aflags,
}

-- #############################################

function dissect_socket(subtree, buffer, offset)
  local sock_baselen = 4
  local sock_protolen = 0
  buffer = buffer(offset)
  local sock_family = bit.band(buffer(0,4):uint(), 0xFFFF0000)

  if(sock_family == SOCKET_FLAG_AF_INET) then
    sock_protolen = 4
  elseif(sock_family == SOCKET_FLAG_AF_INET6) then
    sock_protolen = 16
  end

  local totlen = sock_baselen + sock_protolen
  local socktree = subtree:add(socket_info, buffer(0, totlen))

  socktree:add(socket_family, buffer(0, 2))
  socktree:add(socket_port, buffer(2, 2))

  if(sock_family == SOCKET_FLAG_AF_INET) then
    socktree:add(socket_ipv4, buffer(4, sock_protolen))
  elseif(sock_family == SOCKET_FLAG_AF_INET6) then
    socktree:add(socket_ipv6, buffer(4, sock_protolen))
  end

  return offset+totlen, socktree
end

-- #############################################

function dissect_register(subtree, buffer, flags)
  local regtree = subtree:add(register_field, buffer)

  regtree:add(register_cookie, buffer(0,4))
  regtree:add(src_mac, buffer(4,6))
  regtree:add(dst_mac, buffer(10,6))

  if(bit.band(flags, FLAG_SOCKET) == FLAG_SOCKET) then
    idx = dissect_socket(regtree, buffer, 16)
  else
    idx = 16
  end

  regtree:add(register_ipv4, buffer(idx,4))
  regtree:add(register_ipv4_masklen, buffer(idx+4,1))
  regtree:add(register_desc, buffer(idx+5,16))

  return regtree
end

-- #############################################

function dissect_register_ack(subtree, buffer, flags)
  local regtree = subtree:add(register_ack_field, buffer)

  regtree:add(register_ack_cookie, buffer(0,4))
  regtree:add(src_mac, buffer(4,6))
  regtree:add(dst_mac, buffer(10,6))

  if(bit.band(flags, FLAG_SOCKET) == FLAG_SOCKET) then
    dissect_socket(subtree, buffer, 16)
  end

  return regtree
end

-- #############################################

function dissect_packet(subtree, buffer, flags, pinfo)
  local pktree = subtree:add(packet_field, buffer)

  pktree:add(src_mac, buffer(0,6))
  pktree:add(dst_mac, buffer(6,6))

  if(bit.band(flags, FLAG_SOCKET) == FLAG_SOCKET) then
    idx = dissect_socket(pktree, buffer, 12)
  else
    idx = 12
  end

  pktree:add(packet_compression, buffer(idx,1))
  pktree:add(packet_transform, buffer(idx+1,1))

  local transform = buffer(idx,1):uint()
  -- local compression = buffer(idx+1,1):uint()

  local dis

  -- Can only dissect unencrypted data
  -- FIXME: compression!
  if(transform == PKT_TRANSFORM_NULL) then
    dis = Dissector.get("eth_withoutfcs")
  else
    dis = Dissector.get("data")
  end

  dis:call(buffer(idx+2):tvb(), pinfo, pktree)


  return pktree
end

-- #############################################

function dissect_register_super(subtree, buffer, flags)
  local regtree = subtree:add(register_super_field, buffer)

  regtree:add(register_super_cookie, buffer(0,4))
  regtree:add(src_mac, buffer(4,6))

  if(bit.band(flags, FLAG_SOCKET) == FLAG_SOCKET) then
    idx = dissect_socket(subtree, buffer, 10)
  else
    idx = 10
  end

  regtree:add(register_ipv4, buffer(idx,4))
  regtree:add(register_ipv4_masklen, buffer(idx+4,1))
  regtree:add(register_desc, buffer(idx+5,16))
  idx = idx + 21

  regtree:add(register_super_auth_schema, buffer(idx,2))
  regtree:add(register_super_auth_size, buffer(idx+2,2))

  local auth_size = buffer(idx+2,2):uint()
  regtree:add(register_super_auth_data, buffer(idx+4,auth_size))
  idx = idx + 4 + auth_size

  regtree:add(register_super_key_time, buffer(idx,4))

  return regtree
end

-- #############################################

function dissect_register_super_ack(subtree, buffer, flags)
  local regtree = subtree:add(register_super_ack_field, buffer)

  regtree:add(register_super_ack_cookie, buffer(0,4))
  regtree:add(src_mac, buffer(4,6))
  regtree:add(register_ipv4, buffer(10,4))
  regtree:add(register_ipv4_masklen, buffer(14,1))
  regtree:add(register_super_ack_lifetime, buffer(15,2))

  local idx = dissect_socket(regtree, buffer, 17)

  regtree:add(register_super_auth_schema, buffer(idx,2))
  regtree:add(register_super_auth_size, buffer(idx+2,2))

  local auth_size = buffer(idx+2,2):uint()
  regtree:add(register_super_auth_data, buffer(idx+4,auth_size))
  idx = idx + 4 + auth_size

  regtree:add(register_super_ack_num_sn, buffer(idx, 1))
  local num_sn = buffer(idx,1):uint()
  idx = idx + 1

  local sn_info_len = 26 * num_sn
  local sn_tree = regtree:add(supernode_info, buffer(idx, sn_info_len))

  -- TODO: for loop over sn info
  -- - decode supernode buffer - array of num_sn of:
  --    uint8_t sock[20]
  --    n2n_max_t mac
  if num_sn > 0 then
      dissect_socket(sn_tree, buffer, idx)
      sn_tree:add(src_mac, buffer(idx+20,6))
  end

  idx = idx + sn_info_len

  regtree:add(register_super_key_time, buffer(idx,4))


  return regtree
end

-- #############################################

function dissect_peer_info(subtree, buffer, flags)
  local peertree = subtree:add(peer_info_field, buffer)

  peertree:add(peer_info_flags, buffer(0,2))
  peertree:add(peer_info_mac, buffer(2,6))
  dissect_socket(peertree, buffer, 8)

  return peertree
end

-- #############################################

function dissect_query_peer(subtree, buffer, flags)
  local peertree = subtree:add(query_peer_field, buffer)

  peertree:add(src_mac, buffer(0,6))
  peertree:add(dst_mac, buffer(6,6))
  peertree:add(aflags, buffer(12,2))

  return peertree
end

-- #############################################

function n3n.dissector(buffer, pinfo, tree)
  local length = buffer:len()
  if length < 20 then return end

  pinfo.cols.protocol = n3n.name

  local pkt_type = bit.band(buffer(2,2):uint(), packet_type_mask)
  local subtree = tree:add(n3n, buffer(), string.format("n3n Protocol, Type: %s", pkt_type_2_str[pkt_type] or "Unknown"))

  -- Common
  subtree:add(version, buffer(0,1))
  subtree:add(ttl, buffer(1,1))
  subtree:add(packet_type, buffer(2,2))
  local flags_buffer = buffer(2,2)
  local flags_tree = subtree:add(flags, flags_buffer)
  subtree:add(community, buffer(4,20))

  -- Flags
  flags_tree:add(from_supernode_flag, flags_buffer)
  flags_tree:add(socket_flag, flags_buffer)

  -- Packet specific
  local flags = bit.band(buffer(2,2):uint(), flags_mask)
  local typebuf = buffer(24)

  if(pkt_type == PKT_TYPE_REGISTER) then
    dissect_register(subtree, typebuf, flags)
  elseif(pkt_type == PKT_TYPE_REGISTER_ACK) then
    dissect_register_ack(subtree, typebuf, flags)
  elseif(pkt_type == PKT_TYPE_PACKET) then
    dissect_packet(subtree, typebuf, flags, pinfo)
  elseif(pkt_type == PKT_TYPE_REGISTER_SUPER) then
    dissect_register_super(subtree, typebuf, flags)
  elseif(pkt_type == PKT_TYPE_REGISTER_SUPER_ACK) then
    dissect_register_super_ack(subtree, typebuf, flags)
  elseif(pkt_type == PKT_TYPE_PEER_INFO) then
    dissect_peer_info(subtree, typebuf, flags)
  elseif(pkt_type == PKT_TYPE_QUERY_PEER) then
    dissect_query_peer(subtree, typebuf, flags)
  end
end

-- #############################################

local udp_port = DissectorTable.get("udp.port")
udp_port:add(50001, n3n)
