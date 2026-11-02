-- Build gate, run with `pandoc lua`. It fails when dist/ holds a page not on the allowlist,
-- misses one, carries an internal file, breaks an internal link or fragment, lacks the nav,
-- or exposes a local path.
local sys, path = pandoc.system, pandoc.path
local site, dist = arg[1], arg[2]
local errors = {}
local function fail(m) errors[#errors + 1] = m end

local expected, count = {}, 0
for line in io.lines(site .. "/allow.txt") do
  local p = line:match("^([^#|][^|]*)|")
  if p then
    if p:match("docs/next%.md") or p:match("docs/execution%.md") or p:match("docs/notebook%.md")
      or p:match("docs/review/") or p:match("docs/dst/") or p:match("docs/research/") then
      fail("allow.txt names an internal file: " .. p)
    end
    expected[(p:gsub("README%.md$", "index.html"):gsub("%.md$", ".html"))] = true
    count = count + 1
  end
end

local files = {}
local function walk(dir, rel)
  for _, name in ipairs(sys.list_directory(dir)) do
    local full, r = dir .. "/" .. name, rel == "" and name or rel .. "/" .. name
    local ok, sub = pcall(sys.list_directory, full)
    if ok and sub then walk(full, r) else files[r] = full end
  end
end
walk(dist, "")

local function read(p) local f = assert(io.open(p, "rb")); local s = f:read("a"); f:close(); return s end
local html, ids = {}, {}
for rel, full in pairs(files) do
  if rel:match("%.html$") then
    html[rel] = read(full)
    ids[rel] = {}
    for id in html[rel]:gmatch('%sid="([^"]*)"') do ids[rel][id] = true end
    if rel ~= "index.html" and not expected[rel] then fail("page not on the allowlist: " .. rel) end
  end
end
for rel in pairs(expected) do if not html[rel] then fail("allowlisted page missing: " .. rel) end end

local function decode(s)
  s = s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
  return (s:gsub("&amp;", "&"))
end

-- pandoc.path.normalize keeps "..", so relative targets are collapsed by hand.
local function resolve(dir, rel)
  local parts = {}
  for p in (dir .. "/" .. rel):gmatch("[^/]+") do
    if p == ".." then table.remove(parts) elseif p ~= "." then parts[#parts + 1] = p end
  end
  return table.concat(parts, "/")
end

local links = 0
for rel, body in pairs(html) do
  local dir = path.directory(rel)
  for _, attr in ipairs({ "href", "src" }) do
    for target in body:gmatch("%s" .. attr .. '="([^"]*)"') do
      if not target:match("^%a[%w+.-]*:") then
        links = links + 1
        local file, frag = target:match("^([^#]*)#?(.*)$")
        local to = file == "" and rel or resolve(dir, decode(file))
        if not files[to] then
          fail(rel .. ": broken link " .. target)
        elseif frag ~= "" and html[to] and not ids[to][decode(frag)] then
          fail(rel .. ": broken fragment " .. target)
        end
      end
    end
  end

  -- A local path in a published page leaks the author's machine layout.
  for line in (body .. "\n"):gmatch("([^\n]*)\n") do
    if line:match("/Users/") or line:match("/private/tmp") then
      fail(rel .. ": local path: " .. line:sub(1, 110))
    end
  end

  -- Every document page must reach every other one through its own nav.
  if rel ~= "index.html" then
    local _, depth = rel:gsub("/", "")
    local up = string.rep("../", depth)
    for other in pairs(expected) do
      if not body:find('<li><a href="' .. up .. other .. '"', 1, true) then
        fail(rel .. ": nav lacks " .. other)
      end
    end
  end
end

table.sort(errors)
for _, e in ipairs(errors) do io.stderr:write("FAIL " .. e .. "\n") end
print(string.format("check: %d allowlisted pages, %d internal links, %d failures", count, links, #errors))
if #errors > 0 then os.exit(1) end
