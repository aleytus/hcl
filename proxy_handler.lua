local socket = require("socket.core")
local ffi = require("ffi")
local bindings = require("bindings")
local C = bindings.crypto
local SSL = bindings.ssl
local SSL_UTILS = require("ssl_utils")
local HTTP_PARSER = require("http_parser")
local NGHTTP2_HANDLER = require("nghttp2_handler")
local CACHE_LOGIC = require("cache_logic")
local FFI_SSL_Socket = require("ffi_ssl_socket")

local TIMEOUT = 10

local ProxyHandler = {}
ProxyHandler.__index = ProxyHandler

local function get_raw_socket(sock)
    if sock.get_sock then
        return sock:get_sock()
    end
    return sock
end

function ProxyHandler:new(client_socket, ca_key, ca_cert)
    local self = setmetatable({
        client = client_socket,
        ca_key = ca_key,
        ca_cert = ca_cert,
        client_ssl = nil,
        remote_ssl = nil,
        remote_sock = nil,
        request_buffer = ""
    }, ProxyHandler)
    return self
end

function ProxyHandler:close()
    if self.client_ssl then
        pcall(self.client_ssl.close, self.client_ssl)
        self.client_ssl = nil
    end
    if self.remote_ssl then
        pcall(self.remote_ssl.close, self.remote_ssl)
        self.remote_ssl = nil
    end
    if self.remote_sock then
        pcall(self.remote_sock.close, self.remote_sock)
        self.remote_sock = nil
    end
    if self.client then
        pcall(self.client.close, self.client)
        self.client = nil
    end
end

function ProxyHandler:run_tcp_passthrough(sock1, sock2)
    local raw_sock1 = get_raw_socket(sock1)
    local raw_sock2 = get_raw_socket(sock2)
    
    local sockets = { [raw_sock1] = sock1, [raw_sock2] = sock2 }
    local peers = { [raw_sock1] = sock2, [raw_sock2] = sock1 }
    local raw_peers = { [raw_sock1] = raw_sock2, [raw_sock2] = raw_sock1 }
    local bufs = { [raw_sock1] = "", [raw_sock2] = "" }

    while true do
        local read_fds = {}
        local write_fds = {}
        
        if bufs[raw_sock1] == nil or bufs[raw_sock2] == nil then return true end

        if #bufs[raw_sock1] == 0 then table.insert(read_fds, raw_sock1) end
        if #bufs[raw_sock2] == 0 then table.insert(read_fds, raw_sock2) end
        
        if #bufs[raw_sock1] > 0 then table.insert(write_fds, raw_sock2) end
        if #bufs[raw_sock2] > 0 then table.insert(write_fds, raw_sock1) end

        if #read_fds == 0 and #write_fds == 0 then return true end

        local r, w, e = socket.select(
            #read_fds > 0 and read_fds or nil, 
            #write_fds > 0 and write_fds or nil, 
            TIMEOUT
        )
        
        if not r and not w then
            return nil, e or "passthrough select error"
        end
        
        local read_map, write_map = {}, {}
        for _, sock in ipairs(r or {}) do read_map[sock] = true end
        for _, sock in ipairs(w or {}) do write_map[sock] = true end

        for _, raw_sock in ipairs(read_fds) do
            if read_map[raw_sock] then
                local data, err = sockets[raw_sock]:read_nonblock(65536)
                if data then
                    bufs[raw_sock] = data
                elseif err ~= "timeout" and err ~= "want_write" and err ~= "want_read" then
                    bufs[raw_sock] = nil
                    bufs[raw_peers[raw_sock]] = nil
                    return nil, "read error: " .. err
                end
            end
        end

        for _, raw_sock in ipairs(write_fds) do
            if write_map[raw_sock] and bufs[raw_peers[raw_sock]] and #bufs[raw_peers[raw_sock]] > 0 then
                local data_to_write = bufs[raw_peers[raw_sock]]
                local ok, err = sockets[raw_sock]:write_nonblock(data_to_write, #data_to_write)
                if ok then
                    bufs[raw_peers[raw_sock]] = ""
                elseif err ~= "timeout" and err ~= "want_read" and err ~= "want_write" then
                    bufs[raw_sock] = nil
                    bufs[raw_peers[raw_sock]] = nil
                    return nil, "write error: " .. err
                end
            end
        end
    end
end

function ProxyHandler:handle_h11_connect(req)
    local host, port = req.url:match("([^:]+):(%d+)")
    port = tonumber(port) or 443
    
    local ok_send, err_send = self.client:send("HTTP/1.1 200 Connection established\r\nProxy-Agent: HandyCache\r\n\r\n")
    if not ok_send then return nil, "send 200 OK failed: " .. (err_send or "unknown") end
    
    local server_ctx, err_ctx = SSL_UTILS.get_server_ctx(host, self.ca_key, self.ca_cert)
    if not server_ctx then return nil, "get_server_ctx failed: " .. err_ctx end
    
    local client_ssl, err_client_ssl = FFI_SSL_Socket:new(self.client, server_ctx, true)
    if not client_ssl then return nil, "FFI_SSL_Socket (client) failed: " .. err_client_ssl end
    self.client_ssl = client_ssl
    
    local ok_c_hs, err_c_hs = client_ssl:handshake()
    if not ok_c_hs then return nil, "client handshake failed: " .. err_c_hs end
    
    local client_alpn = client_ssl:get_alpn_selected() or "http/1.1"
    
    local remote_sock = socket.tcp()
    remote_sock:settimeout(TIMEOUT)
    local ok_conn, err_conn = remote_sock:connect(host, port)
    if not ok_conn then return nil, "remote connect failed: " .. err_conn end
    self.remote_sock = remote_sock
    
    local client_ctx, err_client_ctx = SSL_UTILS.create_client_ctx(client_alpn == "h2")
    if not client_ctx then return nil, "create_client_ctx failed: " .. (err_client_ctx or "") end
    
    local remote_ssl, err_remote_ssl = FFI_SSL_Socket:new(remote_sock, client_ctx, false)
    if not remote_ssl then return nil, "FFI_SSL_Socket (remote) failed: " .. err_remote_ssl end
    self.remote_ssl = remote_ssl
    
    local ok_r_hs, err_r_hs = remote_ssl:handshake()
    if not ok_r_hs then return nil, "remote handshake failed: " .. err_r_hs end
    
    local remote_alpn = remote_ssl:get_alpn_selected() or "http/1.1"
    
    if client_alpn == "h2" and remote_alpn == "h2" then
        local h2_handler, err_h2 = NGHTTP2_HANDLER:new(client_ssl, remote_ssl, host)
        if not h2_handler then return nil, "NGHTTP2_HANDLER:new failed: " .. (err_h2 or "") end
        
        local ok_h2_proxy, err_h2_proxy = h2_handler:run_proxy_loop()
        if not ok_h2_proxy then print("H2 proxy loop failed: " .. err_h2_proxy) end
    else
        local ok_pt, err_pt = self:run_tcp_passthrough(client_ssl, remote_ssl)
        if not ok_pt then print("TCP passthrough failed: " .. err_pt) end
    end
    
    return true
end

function ProxyHandler:run_h11_streaming_proxy(req, key, meta)
    local host, port = req.host:match("([^:]+):?(%d*)")
    port = (port and #port > 0 and tonumber(port)) or 80

    local remote_sock = socket.tcp()
    remote_sock:settimeout(TIMEOUT)
    local ok_conn, err_conn = remote_sock:connect(host, port)
    if not ok_conn then return nil, "remote connect failed: " .. err_conn end
    self.remote_sock = remote_sock
    
    local path = req.url
    if path:sub(1, 7) == "http://" then
        path = path:match("^http://[^/]+(.*)$")
    end
    if not path or path == "" then path = "/" end
    
    local h11_request_lines = {
        string.format("%s %s %s\r\n", req.method, path, req.proto or "HTTP/1.1")
    }
    
    for k, v in pairs(req.headers) do
        local key_lower = k:lower()
        if key_lower ~= "proxy-connection" and key_lower ~= "connection" and key_lower ~= "keep-alive" and key_lower ~= "transfer-encoding" then
            table.insert(h11_request_lines, string.format("%s: %s\r\n", k, v))
        end
    end
    
    if meta and meta.status == "STALE" then
        if meta.etag then req.headers["if-none-match"] = meta.etag end
        if meta.last_modified then req.headers["if-modified-since"] = meta.last_modified end
    end
    
    table.insert(h11_request_lines, "Connection: close\r\n")
    table.insert(h11_request_lines, "\r\n")
    
    local request_to_send = table.concat(h11_request_lines) .. (req.body or "")
    
    local ok_send, err_send = remote_sock:send(request_to_send)
    if not ok_send then return nil, "remote send failed: " .. err_send end

    local headers_sent = false
    local response_buffer = ""
    local response_headers = {}
    local status_code = 0
    local cacheable = false
    local cache_writer = nil

    while true do
        local chunk, err_recv = remote_sock:receive(65536)
        
        if chunk and #chunk > 0 then
            if not headers_sent then
                response_buffer = response_buffer .. chunk
                local headers_end = response_buffer:find("\r\n\r\n")
                
                if headers_end then
                    headers_sent = true
                    local header_part = response_buffer:sub(1, headers_end)
                    local body_chunk = response_buffer:sub(headers_end + 4)
                    
                    status_code, response_headers = HTTP_PARSER.parse_http11_response_headers(header_part)

                    if meta and meta.status == "STALE" and status_code == 304 then
                        self.client:send(HTTP_PARSER.build_http11_response(meta.status_code, "OK", meta.headers))
                        local body_reader = CACHE_LOGIC.get_cache_body_reader(key)
                        if body_reader then
                            for body_data in body_reader do
                                self.client:send(body_data)
                            end
                        end
                        CACHE_LOGIC.update_cache_meta(key, meta)
                        return true
                    end
                    
                    self.client:send(header_part .. "\r\n\r\n")
                    
                    cacheable = CACHE_LOGIC.is_cacheable(req.method, status_code, response_headers)
                    if cacheable then
                        cache_writer = CACHE_LOGIC.get_cache_body_writer(key)
                        if cache_writer then
                            cache_writer(body_chunk)
                        end
                    end
                    
                    if #body_chunk > 0 and not cacheable then
                        self.client:send(body_chunk)
                    end
                end
            else
                if cache_writer then
                    cache_writer(chunk)
                else
                    self.client:send(chunk)
                end
            end
        end

        if err_recv == "closed" or (not chunk and not err_recv) then
            if cache_writer then
                cache_writer(nil) 
                CACHE_LOGIC.save_cache_meta(key, status_code, response_headers)
            end
            break
        end

        if not chunk and err_recv ~= "timeout" then
             return nil, "remote recv error: " .. err_recv
        end
    end
    return true
end

function ProxyHandler:handle_plain_http(req)
    local host = req.host
    local key = CACHE_LOGIC.get_cache_key(req.method, host .. req.url)
    local status, meta = CACHE_LOGIC.check_cache(key)
    
    if status == "HIT" then
        self.client:send(HTTP_PARSER.build_http11_response(meta.status_code, "OK", meta.headers))
        local body_reader = CACHE_LOGIC.get_cache_body_reader(key)
        if body_reader then
            for body_data in body_reader do
                self.client:send(body_data)
            end
        end
        return true
    end
    
    return self:run_h11_streaming_proxy(req, key, {status=status, etag=meta and meta.etag, last_modified=meta and meta.last_modified})
end

function ProxyHandler:handle_request()
    local headers_end = nil
    while #self.request_buffer < 8192 do
        local data, err_recv = self.client:receive(4096)
        if data and #data > 0 then
            self.request_buffer = self.request_buffer .. data
            headers_end = self.request_buffer:find("\r\n\r\n", 1, true)
            if headers_end then
                break
            end
        else
            if err_recv ~= "timeout" and err_recv ~= "closed" then
                print("Client initial receive error: " .. (err_recv or "unknown"))
            end
            return
        end
    end

    if not headers_end then
        print("Failed to find headers end")
        return
    end

    local req, err_parse, body_start = HTTP_PARSER.parse_http11_request(self.request_buffer)
    
    if not req then
        print("Failed to parse request: " .. (err_parse or "unknown"))
        self.client:send("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        return
    end
    
    if req.body then
        self.request_buffer = ""
    else
        self.request_buffer = self.request_buffer:sub(body_start)
    end
    
    if req.method == "CONNECT" then
        local ok, err = self:handle_h11_connect(req)
        if not ok then print("H1.1 CONNECT failed: " .. (err or "unknown")) end
    elseif req then
        local ok, err = self:handle_plain_http(req)
        if not ok then print("H1.1 Plain HTTP failed: " .. (err or "unknown")) end
    end
end

return ProxyHandler