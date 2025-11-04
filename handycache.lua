local socket = require("socket")
local lanes = require('lanes').configure()
local lfs = require('lfs')
local ffi = require('ffi')

local linda = lanes.linda()
local NUM_WORKERS = 4
local TIMEOUT = 10
local certs_dir = "certs"
local cache_dir = "cache"

local HandyCache = {}
HandyCache.__index = HandyCache

local function ensure_dir(path)
    if not lfs.attributes(path, "mode") then
        pcall(lfs.mkdir, path)
    end
end

function HandyCache:new(host, port)
    ensure_dir(certs_dir)
    ensure_dir(cache_dir)
    
    local SSL_UTILS = require("ssl_utils")
    local ca, err_ca = SSL_UTILS.load_or_generate_ca("certs/ca-key.pem", "certs/ca-cert.pem")
    if not ca then
        error("Failed to load or generate CA certificate: " .. (err_ca or "unknown"))
    end

    local self = setmetatable({
        host = host,
        port = port,
        ca_key = ca.key,
        ca_cert = ca.cert,
    }, HandyCache)
    
    return self
end

local function worker_thread()
    local socket_core = require("socket.core")
    require('lfs')
    require('cjson')
    require('md5')
    local bindings = require("bindings")
    local SSL_UTILS = require("ssl_utils")
    local PROXY_HANDLER = require("proxy_handler")
    
    local linda_worker = require('lanes').configure().linda()
    
    local ca_cert_pem = linda_worker:receive("ca_cert_pem")
    local ca_key_pem = linda_worker:receive("ca_key_pem")
    
    local ca_key, err_key = SSL_UTILS.pem_to_pkey(ca_key_pem)
    local ca_cert, err_cert = SSL_UTILS.pem_to_cert(ca_cert_pem)
    
    if not ca_key or not ca_cert then
        print("Worker fatal error: Could not re-load CA from PEM: " .. (err_key or "") .. " | " .. (err_cert or ""))
        return
    end

    while true do
        local client_socket = linda_worker:receive("client_socket")
        
        if client_socket then
            client_socket:settimeout(TIMEOUT)
            local handler = PROXY_HANDLER:new(client_socket, ca_key, ca_cert)
            
            local ok, err = pcall(handler.handle_request, handler)
            if not ok then
                print("Worker error handling request: " .. (err or "unknown"))
            end
            
            pcall(handler.close, handler)
        end
    end
end


function HandyCache:run()
    local SSL_UTILS = require("ssl_utils")
    
    local key_pem, err_key_pem = SSL_UTILS.pkey_to_pem(self.ca_key)
    local cert_pem, err_cert_pem = SSL_UTILS.cert_to_pem(self.ca_cert)
    
    if not key_pem or not cert_pem then
        print("Fatal: CA PEM conversion error: " .. (err_key_pem or "") .. " | " .. (err_cert_pem or ""))
        return
    end

    print("Starting "..NUM_WORKERS.." worker threads...")
    for i = 1, NUM_WORKERS do
        local worker, err_lane = lanes.gen("*", worker_thread)()
        if not worker then
            print("Failed to launch worker thread: " .. (err_lane or "unknown"))
            return
        end
        linda:send("ca_cert_pem", cert_pem)
        linda:send("ca_key_pem", key_pem)
    end
    
    local server = socket.try(socket.tcp())
    if not server then
        print("Fatal: Could not create socket")
        return
    end
    
    server:setoption("reuseaddr", true)
    local ok_bind, err_bind = server:bind(self.host, self.port)
    if not ok_bind then
        print("Fatal: Could not bind to " .. self.host .. ":" .. self.port .. ": " .. (err_bind or "unknown"))
        server:close()
        return
    end
    server:listen(1024)
    print("Proxy listening on " .. self.host .. ":" .. self.port)

    while true do
        local client, err = server:accept()
        if client then
            linda:send("client_socket", client)
        elseif err ~= "timeout" and err ~= "closed" and err ~= "interrupted" then
            print("Accept error: " .. (err or "unknown"))
        end
    end
end

return HandyCache