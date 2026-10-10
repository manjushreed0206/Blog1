description = [[
  Enhanced DNS Multi-Record Reconnaissance Scanner.
  Enhances Nmap's built-in dns-recursion script. Instead of a single
  yes/no recursion check, it queries the target DNS server for several
  record types and prints the ACTUAL VALUES returned (A, AAAA, NS),
  reports MX and SOA presence, and checks whether the response is
  DNSSEC-signed (presence of RRSIG records). Discovery only.
]]
author = "Manjushree"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local dns = require "dns"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

portrule = shortport.portnumber(53, {"udp", "tcp"})

-- Query one record type and return a list of answer values, or nil.
local function query_all(host, port, domain, dtype)
  local opts = { host = host.ip, port = port.number,
                 proto = port.protocol, dtype = dtype, retAll = true }
  local ok, status, result = pcall(dns.query, domain, opts)
  if ok and status and result then
    if type(result) ~= "table" then result = { result } end
    return result
  end
  return nil
end

action = function(host, port)
  local domain = stdnse.get_script_args(SCRIPT_NAME .. ".domain") or "google.com"
  local out = {}

  table.insert(out, "==================================================================")
  table.insert(out, "        ENHANCED DNS RECONNAISSANCE SCAN REPORT                   ")
  table.insert(out, "==================================================================")
  table.insert(out, "[*] Domain queried       : " .. domain)

  -- A, AAAA, NS: print the actual values returned
  local sets = {
    { "A",    "IPv4 Address (A)" },
    { "AAAA", "IPv6 Address (AAAA)" },
    { "NS",   "Name Servers (NS)" },
  }
  for _, s in ipairs(sets) do
    local vals = query_all(host, port, domain, s[1])
    if vals and #vals > 0 then
      table.insert(out, "[+] " .. s[2] .. ":")
      for _, v in ipairs(vals) do
        table.insert(out, "      - " .. tostring(v))
      end
    else
      table.insert(out, "[-] " .. s[2] .. " : NOT RETURNED")
    end
  end

  -- MX and SOA: report presence
  local mx = query_all(host, port, domain, "MX")
  table.insert(out, (mx and #mx > 0)
    and "[+] Mail Servers (MX)    : PRESENT"
    or  "[-] Mail Servers (MX)    : NOT RETURNED")

  local soa = query_all(host, port, domain, "SOA")
  table.insert(out, (soa and #soa > 0)
    and "[+] SOA Record           : PRESENT"
    or  "[-] SOA Record           : NOT RETURNED")

  -- DNSSEC: query with the DO bit set and look for RRSIG (type 46) in the answer
  local signed = false
  local ok, status, pkt = pcall(dns.query, domain,
    { host = host.ip, port = port.number, proto = port.protocol,
      dtype = "A", dnssec = true, retPkt = true })
  if ok and status and type(pkt) == "table" and pkt.answers then
    for _, rr in ipairs(pkt.answers) do
      if rr.dtype == 46 then
        signed = true
        break
      end
    end
  end
  table.insert(out, signed
    and "[+] DNSSEC (RRSIG)       : SIGNED RESPONSE"
    or  "[-] DNSSEC (RRSIG)       : NO RRSIG IN ANSWER")

  table.insert(out, "==================================================================")
  return stdnse.format_output(true, out)
end
