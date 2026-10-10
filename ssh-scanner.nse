description = [[
  SSH Protocol & Banner Discovery Scanner.
  Performs discovery scanning for SSH service attributes:
    - SSH Server Banner Extraction
    - SSH Protocol Version Identification (SSHv1 vs SSHv2)
    - Software Distribution Identification
    - Service Port Accessibility State
]]
author = "Manjushree"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

portrule = shortport.portnumber(22, "tcp")

action = function(host, port)
  local results = {}

  table.insert(results, "==================================================================")
  table.insert(results, "             SSH SERVICE DISCOVERY SCAN REPORT                    ")
  table.insert(results, "==================================================================")

  local socket = nmap.new_socket()
  socket:set_timeout(5000)
  local status, err = socket:connect(host.ip, port.number)
  local banner_line = ""
  if status then
    local status_resp, line = socket:receive_lines(1)
    if status_resp and line then
      banner_line = line:gsub("%s+", "")
    end
    socket:close()
  end

  table.insert(results, string.format("[+] Target IP            : %s", host.ip))
  table.insert(results, string.format("[+] Target Port          : %d/tcp", port.number))

  if banner_line ~= "" then
    table.insert(results, "[+] SSH Banner           : " .. banner_line)
  else
    table.insert(results, "[-] SSH Banner           : NOT DISCLOSED / TIMEOUT")
  end

  if banner_line ~= "" and (string.match(banner_line, "1%.5") or string.match(banner_line, "1%.99")) then
    table.insert(results, "[+] Protocol Version     : SSHv1 Enabled (Legacy)")
  elseif banner_line ~= "" and string.match(banner_line, "2%.0") then
    table.insert(results, "[+] Protocol Version     : SSHv2 Only")
  else
    table.insert(results, "[-] Protocol Version     : UNKNOWN")
  end

  if banner_line ~= "" and string.match(banner_line, "OpenSSH") then
    table.insert(results, "[+] Software Detected    : OpenSSH")
  elseif banner_line ~= "" then
    table.insert(results, "[+] Software Detected    : Custom / Proprietary SSH")
  end

  table.insert(results, "==================================================================")
  return stdnse.format_output(true, results)
end
