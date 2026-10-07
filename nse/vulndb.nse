local json = require "json"
local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Reports candidate CVEs for detected service versions from a local Offline
VulnDB database, with CISA KEV and public-exploit evidence and, for Ubuntu,
Debian and Red Hat-family packages, distribution backport verdicts. No
network access: everything is answered by the local `vulndb` binary.

The script is a thin adapter. It sends the port's service fingerprint (and
the host's other open ports, which provide distribution evidence) to
`vulndb nse` and prints the answer. Results are candidate vulnerabilities
based on product/version data, not proof that the target is vulnerable.

Requires version detection (-sV). Unix-like systems only (the binary is run
via the shell; Windows is untested).
]]

---
-- @usage
-- nmap -sV --script vulndb --script-args vulndb.bin=/opt/vulndb/vulndb,vulndb.db=/opt/vulndb/vulndb.sqlite <target>
--
-- @args vulndb.bin     Path to the vulndb binary (default: "vulndb" on PATH).
-- @args vulndb.db      Path to the database (default: vulndb's own default,
--                      $VULNDB_DB or ./vulndb.sqlite).
-- @args vulndb.max     Maximum CVEs listed per port (default 10).
-- @args vulndb.mincvss Hide CVEs with a CVSS score below this (default 0).
-- @args vulndb.showall Also list undetermined CVEs and CVEs fixed in the
--                      distribution package (default false).
--
-- @output
-- 22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
-- | vulndb:
-- |   6 candidate CVEs (0 in CISA KEV, 0 with public exploit evidence)
-- |   Distribution: Ubuntu 24.04 installed 1:9.6p1-3ubuntu13.18; 16 more fixed in the package
-- |   CVE-2026-73282   MEDIUM    CVSS 4.8  Ubuntu: VULNERABLE
-- |_  CVE-2023-51767   HIGH      CVSS 7.0
--
-- @xmloutput
-- <elem key="assessment">ASSESSED</elem>
-- <table key="vulns">
--   <table>
--     <elem key="id">CVE-2026-73282</elem>
--     <elem key="severity">MEDIUM</elem>
--     <elem key="cvss">4.8</elem>
--     <elem key="kev">false</elem>
--     <elem key="exploit">false</elem>
--     <elem key="version_status">MATCH</elem>
--     <elem key="distro">Ubuntu: VULNERABLE</elem>
--   </table>
-- </table>

author = "Offline VulnDB"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

local REQUEST_VERSION = 1

-- Only ports whose service was fingerprinted by -sV (not guessed from the
-- port number) and that carry a product or CPE.
portrule = function(host, port)
  local v = port.version
  return v ~= nil and v.service_dtype == "probed"
    and ((v.product and v.product ~= "") or (v.cpe and #v.cpe > 0))
end

-- POSIX shell single-quoting. Only trusted values (script arguments and the
-- temporary file name) are ever placed on the command line.
local function q(s)
  return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

local function port_entry(p)
  local v = p.version or {}
  return {
    protocol = p.protocol,
    port = p.number,
    state = "open",
    name = v.name or "",
    product = v.product or "",
    version = v.version or "",
    extrainfo = v.extrainfo or "",
    ostype = v.ostype or "",
    tunnel = v.service_tunnel == "ssl" and "ssl" or "",
    method = v.service_dtype or "",
    conf = math.tointeger(math.floor(tonumber(v.name_confidence) or 0)),
    cpes = json.make_array(v.cpe or {}),
  }
end

-- The host's open ports: other services provide distribution evidence
-- (e.g. Apache "(Red Hat Enterprise Linux)" for an unmarked OpenSSH).
local function host_ports(host)
  local ports = {}
  for _, proto in ipairs({"tcp", "udp"}) do
    local p = nmap.get_ports(host, nil, proto, "open")
    while p do
      if p.version and p.version.service_dtype == "probed" then
        ports[#ports + 1] = port_entry(p)
      end
      p = nmap.get_ports(host, p, proto, "open")
    end
  end
  return ports
end

local function os_cpes(host)
  local out = {}
  for _, match in ipairs(host.os or {}) do
    for _, class in ipairs(match.classes or {}) do
      for _, c in ipairs(class.cpe or {}) do
        out[#out + 1] = c
      end
    end
  end
  return out
end

local function run_vulndb(request)
  local bin = stdnse.get_script_args("vulndb.bin") or "vulndb"
  local db = stdnse.get_script_args("vulndb.db")
  local path = os.tmpname()
  local f, err = io.open(path, "w")
  if not f then
    return nil, "cannot write request file: " .. tostring(err)
  end
  local body = json.generate(request)
  stdnse.debug2("request: %s", body)
  f:write(body)
  f:close()

  local cmd = q(bin)
  if db then
    cmd = cmd .. " --db " .. q(db)
  end
  cmd = cmd .. " nse --request " .. q(path) .. " 2>/dev/null"
  stdnse.debug2("running: %s", cmd)
  local pipe = io.popen(cmd, "r")
  local out = pipe and pipe:read("a") or ""
  if pipe then pipe:close() end
  os.remove(path)

  stdnse.debug2("response: %s", out)
  local ok, resp = json.parse(out)
  if not ok or type(resp) ~= "table" then
    return nil, "no valid answer from " .. bin .. " (check vulndb.bin and vulndb.db)"
  end
  if resp.error then
    return nil, resp.error
  end
  return resp
end

action = function(host, port)
  local showall = stdnse.get_script_args("vulndb.showall")
  local request = {
    version = REQUEST_VERSION,
    host = {
      address = host.ip,
      hostnames = json.make_array({host.targetname or host.name or nil}),
      os_cpes = json.make_array(os_cpes(host)),
    },
    ports = json.make_array(host_ports(host)),
    target = {protocol = port.protocol, port = port.number},
    options = {
      max = tonumber(stdnse.get_script_args("vulndb.max")) or 10,
      mincvss = tonumber(stdnse.get_script_args("vulndb.mincvss")) or 0,
      show_undetermined = showall ~= nil and showall ~= "false",
      show_distro_fixed = showall ~= nil and showall ~= "false",
    },
  }

  local resp, err = run_vulndb(request)
  if not resp then
    -- Shown at every verbosity: a misconfigured vulndb.bin / vulndb.db must
    -- not look like "no vulnerabilities".
    return "ERROR: " .. err
  end
  local c = resp.counts or {}
  if not request.options.show_undetermined and (c.matches or 0) == 0 and (c.undetermined or 0) == 0 then
    return nil -- nothing to report for this port (vulndb.showall lists everything)
  end

  -- Structured output for -oX; the text lines are rendered by vulndb.
  local out = stdnse.output_table()
  out.assessment = resp.assessment
  if resp.distro and resp.distro ~= "" then
    out.distro = resp.distro
  end
  out.counts = resp.counts
  out.vulns = resp.vulns
  if resp.notes and #resp.notes > 0 then
    out.notes = resp.notes
  end
  return out, "\n  " .. table.concat(resp.lines or {}, "\n  ")
end
