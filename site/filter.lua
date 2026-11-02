-- Pandoc filter for one document page. It maps links through the allowlist, builds the nav
-- from that same list, pre-renders mermaid to static SVG, and frames tables and code so
-- they scroll inside the page instead of widening it.
local env = os.getenv
local src, here, dist, cache = env("SRC"), env("SITE"), env("DIST"), env("CACHE")
local blob = "https://github.com/Roasbeef/pondline/blob/main/"

local function esc(s)
  return (s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;"):gsub('"', "&quot;"))
end

-- A README becomes its directory's index.html, so the directory URL works on Pages too.
local function page(path)
  return (path:gsub("README%.md$", "index.html"):gsub("%.md$", ".html"))
end

local entries, allowed = {}, {}
for line in io.lines(here .. "/allow.txt") do
  if line ~= "" and line:sub(1, 1) ~= "#" then
    local p, g, t = line:match("^([^|]+)|([^|]+)|([^|]+)$")
    entries[#entries + 1] = { path = p, group = g, title = t }
    allowed[p] = true
  end
end

local _, depth = page(src):gsub("/", "")
local root = string.rep("../", depth)

local function norm(dir, rel)
  local parts = {}
  for p in (dir .. rel):gmatch("[^/]+") do
    if p == ".." then table.remove(parts) elseif p ~= "." then parts[#parts + 1] = p end
  end
  return table.concat(parts, "/")
end

function Link(l)
  if l.target:match("^%a[%w+.-]*:") or l.target:match("^#") then return nil end
  local path, frag = l.target:match("^([^#]*)(#?.*)$")
  local full = norm(src:match("^(.*/)") or "", path)
  if allowed[full .. "/README.md"] then full = full .. "/README.md" end
  if allowed[full] then
    l.target = root .. page(full) .. frag
  else
    l.target = blob .. full .. frag
  end
  return l
end

local function render(text, mode, hash)
  local out = cache .. "/" .. hash .. "-" .. mode .. ".svg"
  local f = io.open(out)
  if f then f:close(); return out end
  local input = cache .. "/" .. hash .. ".mmd"
  local w = assert(io.open(input, "w")); w:write(text); w:close()
  local cmd = string.format("mmdc -q -i '%s' -o '%s' -b transparent -c '%s/mermaid-%s.json' --svgId 'm%s'",
    input, out, here, mode, hash)
  if env("CI") then cmd = cmd .. " -p '" .. here .. "/puppeteer-ci.json'" end
  if not os.execute(cmd .. " >&2") then error("mmdc failed on a diagram in " .. src) end
  return out
end

local function diagram(text)
  local hash = pandoc.utils.sha1(text):sub(1, 16)
  local tags = {}
  for _, mode in ipairs({ "light", "dark" }) do
    local svg = render(text, mode, hash)
    local r = assert(io.open(svg)); local body = r:read("a"); r:close()
    local name = hash .. "-" .. mode .. ".svg"
    local w = assert(io.open(dist .. "/diagrams/" .. name, "w")); w:write(body); w:close()
    local vw, vh = body:match('viewBox="[%d.-]+ [%d.-]+ ([%d.]+) ([%d.]+)"')
    tags[#tags + 1] = string.format(
      '<a class="mm-%s" href="%sdiagrams/%s"><img src="%sdiagrams/%s" alt="Diagram. Its source text is under it." width="%d" height="%d" style="min-width:%dpx"></a>',
      mode:sub(1, 1), root, name, root, name, math.ceil(tonumber(vw)), math.ceil(tonumber(vh)), math.ceil(tonumber(vw) * 0.7))
  end
  return pandoc.RawBlock("html", '<figure class="mm">' .. table.concat(tags) ..
    "<details><summary>Diagram source</summary><pre tabindex=\"0\"><code>" .. esc(text) ..
    "</code></pre></details></figure>")
end

function CodeBlock(c)
  if c.classes:includes("mermaid") then return diagram(c.text) end
  return pandoc.RawBlock("html", '<pre tabindex="0"><code>' .. esc(c.text) .. "</code></pre>")
end

-- Pandoc pins column widths on long pipe tables; dropping them lets the browser fit the content.
function Table(t)
  for i, spec in ipairs(t.colspecs) do t.colspecs[i] = { spec[1], nil } end
  return { pandoc.RawBlock("html", '<div class="tw" tabindex="0">'), t, pandoc.RawBlock("html", "</div>") }
end

local function nav()
  local out, groups, seen, current = {}, {}, {}, nil
  for _, e in ipairs(entries) do
    if not seen[e.group] then
      seen[e.group] = {}
      groups[#groups + 1] = e.group
    end
    table.insert(seen[e.group], e)
    if e.path == src then current = e.group end
  end
  for _, g in ipairs(groups) do
    -- Only the long Decisions list folds, and it stays open when the reader is inside it.
    local fold = g == "Decisions"
    if fold then
      out[#out + 1] = "<details" .. (current == g and " open" or "") .. "><summary>" .. esc(g) .. "</summary>"
    else
      out[#out + 1] = "<h2>" .. esc(g) .. "</h2>"
    end
    out[#out + 1] = "<ul>"
    for _, e in ipairs(seen[g]) do
      local cur = e.path == src and ' aria-current="page"' or ""
      out[#out + 1] = string.format('<li><a href="%s%s"%s>%s</a></li>', root, page(e.path), cur, esc(e.title))
    end
    out[#out + 1] = "</ul>"
    if fold then out[#out + 1] = "</details>" end
  end
  return table.concat(out, "\n")
end

function Pandoc(doc)
  local first = doc.blocks[1]
  if first and first.t == "Header" and first.level == 1 then
    doc.meta.title = first.content
    doc.blocks:remove(1)
  end
  doc.meta.pagetitle = pandoc.utils.stringify(doc.meta.title or src)
  doc.meta.root = root
  doc.meta.source = src
  doc.meta.nav = pandoc.MetaBlocks({ pandoc.RawBlock("html", nav()) })
  return doc
end
