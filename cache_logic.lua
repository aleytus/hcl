local lfs = require("lfs")
local md5 = require("md5")
local cjson = require("cjson")

local CACHE_DIR = "cache/"
local DEFAULT_MAX_AGE = 3600

local M = {}

local function get_meta_path(key)
    return CACHE_DIR .. key .. ".meta"
end

local function get_data_path(key)
    return CACHE_DIR .. key .. ".data"
end

local function parse_max_age(cache_control)
    if not cache_control then return nil end
    local s, e, age = cache_control:find("max%-age%s*=%s*(%d+)")
    if age then return tonumber(age) end
    return nil
end

function M.get_cache_key(method, url)
    return md5.sumhexa(method .. ":" .. url)
end

function M.check_cache(key)
    local meta_path = get_meta_path(key)
    
    local f_meta = io.open(meta_path, "r")
    if not f_meta then return "MISS", nil end
    
    local meta_raw = f_meta:read("*a")
    f_meta:close()
    if not meta_raw then return "MISS", nil end
    
    local ok, meta = pcall(cjson.decode, meta_raw)
    if not ok or not meta then return "MISS", nil end
    
    local cache_control = meta.headers["cache-control"] or ""
    if cache_control:match("no-cache") or cache_control:match("must-revalidate") then
        return "STALE", meta
    end
    if cache_control:match("no-store") then
        return "MISS", nil
    end

    local max_age = parse_max_age(cache_control) or DEFAULT_MAX_AGE
    local age = os.time() - (meta.timestamp or 0)
    
    if age > max_age then
        return "STALE", meta
    end
    
    return "HIT", meta
end

function M.is_cacheable(method, status_code, headers)
    if method ~= "GET" then
        return false
    end
    
    if status_code ~= 200 and status_code ~= 301 and status_code ~= 308 then
        return false
    end
    
    local cache_control = headers["cache-control"] or ""
    if cache_control:match("no-store") or cache_control:match("private") then
        return false
    end
    
    return true
end

function M.save_cache_meta(key, status_code, headers)
    local meta_path = get_meta_path(key)
    local meta = {
        timestamp = os.time(),
        status_code = status_code,
        headers = headers,
        etag = headers["etag"],
        last_modified = headers["last-modified"]
    }
    
    local meta_json, err_json = pcall(cjson.encode, meta)
    if not meta_json then return nil, "Failed to encode meta: " .. (err_json or "") end
    
    local f_meta, err_meta = io.open(meta_path, "wb")
    if not f_meta then return nil, "Failed to open meta file: " .. (err_meta or "unknown") end
    f_meta:write(meta_json)
    f_meta:close()
    return true
end

function M.update_cache_meta(key, meta)
    meta.timestamp = os.time()
    local meta_path = get_meta_path(key)
    local meta_json = cjson.encode(meta)
    local f_meta = io.open(meta_path, "wb")
    if f_meta then
        f_meta:write(meta_json)
        f_meta:close()
    end
end

function M.get_cache_body_writer(key)
    local data_path = get_data_path(key)
    local f_data, err_data = io.open(data_path, "wb")
    if not f_data then return nil end
    
    return function(chunk)
        if chunk and #chunk > 0 then
            f_data:write(chunk)
        elseif chunk == nil then
            f_data:close()
        end
    end
end

function M.get_cache_body_reader(key)
    local data_path = get_data_path(key)
    local f_data = io.open(data_path, "rb")
    if not f_data then return nil end
    
    return function()
        local chunk = f_data:read(65536)
        if not chunk then
            f_data:close()
            return nil
        end
        return chunk
    end
end

return M