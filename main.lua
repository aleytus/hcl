local ffi = require("ffi")

print("HandyCache (HTTP/2 MITM Proxy) starting on 127.0.0.1:8080...")

local deps = {"socket", "lanes", "lfs", "cjson", "md5", "bindings"}
local all_ok = true
for _, dep in ipairs(deps) do
    local ok, err = pcall(require, dep)
    if not ok then
        print("Fatal Error: Missing dependency '" .. dep .. "': " .. (err or "not found"))
        all_ok = false
    end
end
if not all_ok then
    print("Please ensure all dependencies are installed.")
    return
end

local bindings = require("bindings")
local handycache = require("handycache")

local proxy
local ok_proxy, proxy_or_err = pcall(handycache.new, handycache, "127.0.0.1", 8080)
if not ok_proxy then
    print("Failed to initialize HandyCache: " .. (proxy_or_err or "unknown"))
    return
end
proxy = proxy_or_err

if proxy then
    print("Using OpenSSL: " .. ffi.string(bindings.crypto.OpenSSL_version(0)))
    
    local ng_ver_ptr = bindings.nghttp2.nghttp2_version(0)
    if ng_ver_ptr ~= ffi.NULL then
        print("Using nghttp2: " .. ffi.string(ng_ver_ptr.version_str))
    else
        print("Using nghttp2: <version unknown>")
    end

    local ok_run, err_run = pcall(proxy.run, proxy)
    if not ok_run then
        print("Fatal Runtime Error: " .. (err_run or "unknown"))
    end
else
    print("Failed to initialize HandyCache.")
end