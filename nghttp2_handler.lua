local ffi = require("ffi")
local ffi_gc = ffi.gc
local bindings = require("bindings")
local C = bindings.crypto
local NGHTTP2 = bindings.nghttp2
local SSL = bindings.ssl
local socket = require("socket.core")
local HTTP_PARSER = require("http_parser")
local CACHE_LOGIC = require("cache_logic")

local M = {}
M.__index = M

local TIMEOUT = 10
local bit_bor = bit.bor

ffi.cdef[[
void* malloc(size_t);
void free(void*);
void* realloc(void*, size_t);

typedef void FFI_SSL_Socket;

typedef struct {
    void *handler;
    void *client_ssl;
    void *remote_ssl;
    char *host;
} nghttp2_session_data;

typedef struct {
    int32_t stream_id;
    int32_t remote_stream_id;
    void *session_data;
    
    char* cache_key;
    char* method;
    char* url;
    int h2_status;
    bool cacheable;
    void* cache_writer_handle;
    void* cache_reader_handle;

    char* data_buffer;
    size_t data_len;
    size_t data_offset;
    
    void* stale_meta;
} nghttp2_stream_data;
]]

local function c_send_callback(session, data, length, flags, user_data)
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local handler = ffi.from_handle(session_data.handler)
    
    local ssl_sock
    if session == handler.client_session then
        ssl_sock = ffi.cast("FFI_SSL_Socket", session_data.client_ssl)
    else
        ssl_sock = ffi.cast("FFI_SSL_Socket", session_data.remote_ssl)
    end
    
    local ok, err = ssl_sock:write_nonblock(data, length)
    
    if ok then
        return length
    end
    
    if err == "want_read" or err == "want_write" then
        return bindings.NGHTTP2_ERR_WOULDBLOCK
    end
    
    return bindings.NGHTTP2_ERR_CALLBACK_FAILURE
end

local function c_recv_callback(session, buf, length, flags, user_data)
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local handler = ffi.from_handle(session_data.handler)
    
    local ssl_sock
    if session == handler.client_session then
        ssl_sock = ffi.cast("FFI_SSL_Socket", session_data.client_ssl)
    else
        ssl_sock = ffi.cast("FFI_SSL_Socket", session_data.remote_ssl)
    end

    local data, err = ssl_sock:read_nonblock(length)
    
    if data then
        ffi.copy(buf, data, #data)
        return #data
    end
    
    if err == "want_read" or err == "want_write" then
        return bindings.NGHTTP2_ERR_WOULDBLOCK
    end
    
    return bindings.NGHTTP2_ERR_CALLBACK_FAILURE
end

local function get_stream_data(handler, stream_id)
    local stream = handler.streams[stream_id]
    if not stream then
        local cdata = ffi_gc(ffi.new("nghttp2_stream_data"), function(s)
            if s.data_buffer ~= ffi.NULL then ffi.C.free(s.data_buffer) end
            if s.cache_writer_handle then
                local writer = ffi.from_handle(s.cache_writer_handle)
                writer(nil)
            end
            if s.cache_reader_handle then ffi.free_handle(s.cache_reader_handle) end
            if s.stale_meta then ffi.free_handle(s.stale_meta) end
        end)
        
        cdata.stream_id = stream_id
        cdata.session_data = ffi.NULL
        cdata.remote_stream_id = 0
        cdata.data_len = 0
        cdata.data_offset = 0
        cdata.data_buffer = ffi.NULL
        cdata.h2_status = 0
        cdata.cache_key = ffi.NULL
        cdata.method = ffi.NULL
        cdata.url = ffi.NULL
        cdata.cacheable = false
        cdata.cache_writer_handle = ffi.NULL
        cdata.cache_reader_handle = ffi.NULL
        cdata.stale_meta = ffi.NULL
        
        stream = {
            cdata = cdata,
            lua_headers = {},
            lua_request_headers = {}
        }
        handler.streams[stream_id] = stream
    end
    return stream
end

local function c_on_begin_headers_callback(session, frame, user_data)
    if frame.hd.type ~= 1 then return 0 end
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local handler = ffi.from_handle(session_data.handler)
    local stream = get_stream_data(handler, frame.hd.stream_id)
    
    if session == handler.client_session then
        stream.lua_request_headers = {}
    else
        stream.lua_headers = {}
    end
    
    return 0
end

local function c_on_header_callback(session, frame, name, namelen, value, valuelen, flags, user_data)
    if frame.hd.type ~= 1 then return 0 end
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local handler = ffi.from_handle(session_data.handler)
    local stream = get_stream_data(handler, frame.hd.stream_id)
    
    local name_str = ffi.string(name, namelen)
    local value_str = ffi.string(value, valuelen)
    
    local headers_table
    if session == handler.client_session then
        headers_table = stream.lua_request_headers
    else
        headers_table = stream.lua_headers
    end

    table.insert(headers_table, name_str)
    table.insert(headers_table, value_str)
    
    if name_str == ":method" then
        stream.cdata.method = value_str
    end
    if name_str == ":path" then
        stream.cdata.url = value_str
    end
    if name_str == ":status" then
        stream.cdata.h2_status = tonumber(value_str)
    end
    return 0
end

local data_read_callback = ffi.cast("ssize_t (*)(void*, int32_t, uint8_t*, size_t, uint32_t*, void*)",
function(session, stream_id, buf, length, data_flags, user_data)
    local cdata = ffi.cast("nghttp2_stream_data*", user_data)
    
    if cdata.data_offset >= cdata.data_len then
        if cdata.data_buffer ~= ffi.NULL then
            ffi.C.free(cdata.data_buffer)
            cdata.data_buffer = ffi.NULL
        end
        cdata.data_len = 0
        cdata.data_offset = 0
        
        if cdata.cache_reader_handle ~= ffi.NULL then
            local reader = ffi.from_handle(cdata.cache_reader_handle)
            local chunk = reader()
            if chunk then
                cdata.data_len = #chunk
                cdata.data_buffer = ffi.C.malloc(cdata.data_len)
                ffi.copy(cdata.data_buffer, chunk, cdata.data_len)
            else
                data_flags[0] = bit_bor(data_flags[0], bindings.NGHTTP2_DATA_FLAG_EOF)
                ffi.free_handle(cdata.cache_reader_handle)
                cdata.cache_reader_handle = ffi.NULL
                return 0
            end
        else
            data_flags[0] = bit_bor(data_flags[0], bindings.NGHTTP2_DATA_FLAG_EOF)
            return 0
        end
    end
    
    local remaining_len = cdata.data_len - cdata.data_offset
    local copy_len = math.min(length, remaining_len)
    
    ffi.copy(buf, cdata.data_buffer + cdata.data_offset, copy_len)
    cdata.data_offset = cdata.data_offset + copy_len
    
    if cdata.data_offset >= cdata.data_len and cdata.cache_reader_handle == ffi.NULL then
        data_flags[0] = bit_bor(data_flags[0], bindings.NGHTTP2_DATA_FLAG_EOF)
        if cdata.data_buffer ~= ffi.NULL then
            ffi.C.free(cdata.data_buffer)
            cdata.data_buffer = ffi.NULL
        end
        cdata.data_len = 0
        cdata.data_offset = 0
    end
    
    return copy_len
end)

local function build_nva(headers_table)
    local nva_list = {}
    local h11_headers = {}
    for i = 1, #headers_table, 2 do
        local k = headers_table[i]
        local v = headers_table[i+1]
        table.insert(nva_list, { name = k, value = v, namelen = #k, valuelen = #v, flags = 0 })
        if k:sub(1,1) ~= ":" then
            h11_headers[k:lower()] = v
        end
    end
    
    local nva_out = ffi.new("nghttp2_nv[?]", #nva_list)
    for i=1, #nva_list do
        nva_out[i-1] = nva_list[i]
    end
    return nva_out, #nva_list, h11_headers
end

local function c_on_frame_recv_callback(session, frame, user_data)
    local stream_id = frame.hd.stream_id
    if stream_id == 0 or frame.hd.type ~= 1 then return 0 end

    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local handler = ffi.from_handle(session_data.handler)
    local stream = get_stream_data(handler, stream_id)
    local cdata = stream.cdata
    cdata.session_data = user_data
    
    local is_client_session = (session == handler.client_session)
    local target_session = is_client_session and handler.remote_session or handler.client_session
    
    local data_prd = nil
    if bit.band(frame.hd.flags, bindings.NGHTTP2_FLAG_END_STREAM) == 0 then
        data_prd = ffi.new("nghttp2_data_provider")
        data_prd.read_callback = data_read_callback
        data_prd.source.ptr = cdata
    end

    if is_client_session then
        local cache_key = CACHE_LOGIC.get_cache_key(cdata.method, ffi.string(session_data.host) .. cdata.url)
        cdata.cache_key = cache_key
        local status, meta = CACHE_LOGIC.check_cache(cache_key)
        
        if status == "HIT" then
            local nva_out, nvlen = build_nva(meta.lua_h2_headers)
            local body_reader = CACHE_LOGIC.get_cache_body_reader(cache_key)
            
            if body_reader then
                cdata.cache_reader_handle = ffi.new_handle(body_reader)
                data_prd = ffi.new("nghttp2_data_provider")
                data_prd.read_callback = data_read_callback
                data_prd.source.ptr = cdata
            end

            NGHTTP2.nghttp2_submit_response(handler.client_session, stream_id, nva_out, nvlen, data_prd)
            return 0
        end

        local req_headers = stream.lua_request_headers
        if status == "STALE" then
            table.insert(req_headers, "if-none-match"); table.insert(req_headers, meta.headers["etag"] or "")
            table.insert(req_headers, "if-modified-since"); table.insert(req_headers, meta.headers["last-modified"] or "")
            cdata.stale_meta = ffi.new_handle(meta)
        end
        
        local nva_out, nvlen = build_nva(req_headers)
        local new_stream_id = NGHTTP2.nghttp2_submit_headers(target_session, 0, -1, ffi.NULL, nva_out, nvlen, data_prd)
        
        if new_stream_id > 0 then
            cdata.remote_stream_id = new_stream_id
            local remote_stream = get_stream_data(handler, new_stream_id)
            remote_stream.cdata.remote_stream_id = stream_id
            remote_stream.cdata.cache_key = cdata.cache_key
            remote_stream.cdata.method = cdata.method
            if cdata.stale_meta then
                remote_stream.cdata.stale_meta = cdata.stale_meta
                cdata.stale_meta = ffi.NULL
            end
        end

    else
        local remote_stream_cdata = get_stream_data(handler, cdata.remote_stream_id).cdata
        if remote_stream_cdata.stale_meta ~= ffi.NULL and cdata.h2_status == 304 then
            local meta = ffi.from_handle(remote_stream_cdata.stale_meta)
            local nva_out, nvlen = build_nva(meta.lua_h2_headers)
            local body_reader = CACHE_LOGIC.get_cache_body_reader(cdata.cache_key)
            if body_reader then
                remote_stream_cdata.cache_reader_handle = ffi.new_handle(body_reader)
                data_prd = ffi.new("nghttp2_data_provider")
                data_prd.read_callback = data_read_callback
                data_prd.source.ptr = remote_stream_cdata
            end
            NGHTTP2.nghttp2_submit_response(target_session, cdata.remote_stream_id, nva_out, nvlen, data_prd)
            CACHE_LOGIC.update_cache_meta(cdata.cache_key, meta)
            return 0
        end

        local nva_out, nvlen, h11_headers = build_nva(stream.lua_headers)
        stream.lua_h11_headers = h11_headers
        cdata.cacheable = CACHE_LOGIC.is_cacheable(remote_stream_cdata.method, cdata.h2_status, h11_headers)
        
        if cdata.cacheable then
            local writer = CACHE_LOGIC.get_cache_body_writer(cdata.cache_key)
            if writer then
                cdata.cache_writer_handle = ffi.new_handle(writer)
            end
        end

        NGHTTP2.nghttp2_submit_response(target_session, cdata.remote_stream_id, nva_out, nvlen, data_prd)
    end
    
    return 0
end

local function c_on_data_chunk_recv_callback(session, flags, stream_id, data, len, user_data)
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local handler = ffi.from_handle(session_data.handler)
    local stream = get_stream_data(handler, stream_id)
    local cdata = stream.cdata

    if cdata.cache_writer_handle ~= ffi.NULL and session == handler.remote_session then
        local writer = ffi.from_handle(cdata.cache_writer_handle)
        writer(ffi.string(data, len))
    end
    
    local target_session = (session == handler.client_session) and handler.remote_session or handler.client_session
    if cdata.remote_stream_id > 0 then
        if cdata.data_buffer == ffi.NULL then
            cdata.data_buffer = ffi.C.malloc(len)
            ffi.copy(cdata.data_buffer, data, len)
            cdata.data_len = len
            cdata.data_offset = 0
        else
            local new_size = cdata.data_len - cdata.data_offset + len
            local new_buf
            if cdata.data_offset > 0 then
                ffi.copy(cdata.data_buffer, cdata.data_buffer + cdata.data_offset, cdata.data_len - cdata.data_offset)
                new_buf = ffi.C.realloc(cdata.data_buffer, new_size)
            else
                new_buf = ffi.C.realloc(cdata.data_buffer, new_size)
            end
            
            if new_buf ~= ffi.NULL then
                cdata.data_buffer = new_buf
                ffi.copy(new_buf + cdata.data_len - cdata.data_offset, data, len)
                cdata.data_len = new_size
                cdata.data_offset = 0
            end
        end
        
        NGHTTP2.nghttp2_session_resume_data(target_session, cdata.remote_stream_id)
    end
    return 0
end

local function c_on_stream_close_callback(session, stream_id, error_code, user_data)
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local handler = ffi.from_handle(session_data.handler)
    
    local stream = handler.streams[stream_id]
    if not stream then return 0 end
    local cdata = stream.cdata
    
    if cdata.cache_writer_handle ~= ffi.NULL and session == handler.remote_session then
        local writer = ffi.from_handle(cdata.cache_writer_handle)
        writer(nil)
        ffi.free_handle(cdata.cache_writer_handle)
        cdata.cache_writer_handle = ffi.NULL
        
        CACHE_LOGIC.save_cache_meta(cdata.cache_key, cdata.h2_status, stream.lua_h11_headers, stream.lua_headers)
    end

    local target_session = (session == handler.client_session) and handler.remote_session or handler.client_session
    if cdata.remote_stream_id > 0 then
        NGHTTP2.nghttp2_submit_rst_stream(target_session, bindings.NGHTTP2_FLAG_NONE, cdata.remote_stream_id, bindings.NGHTTP2_NO_ERROR)
        local remote_stream = handler.streams[cdata.remote_stream_id]
        if remote_stream then
            remote_stream.cdata.remote_stream_id = 0
        end
    end
    
    handler.streams[stream_id] = nil
    return 0
end

local function create_callbacks()
    local cbs_ptr = ffi.new("nghttp2_session_callbacks*[1]")
    NGHTTP2.nghttp2_session_callbacks_new(cbs_ptr)
    local callbacks = ffi_gc(cbs_ptr[0], NGHTTP2.nghttp2_session_callbacks_del)
    
    NGHTTP2.nghttp2_session_callbacks_set_send_callback(callbacks, c_send_callback)
    NGHTTP2.nghttp2_session_callbacks_set_recv_callback(callbacks, c_recv_callback)
    NGHTTP2.nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, c_on_frame_recv_callback)
    NGHTTP2.nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, c_on_data_chunk_recv_callback)
    NGHTTP2.nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, c_on_stream_close_callback)
    NGHTTP2.nghttp2_session_callbacks_set_on_header_callback(callbacks, c_on_header_callback)
    NGHTTP2.nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, c_on_begin_headers_callback)
    
    return callbacks
end

local global_callbacks = create_callbacks()

function M:new(client_ssl, remote_ssl, host)
    local self = setmetatable({
        client_ssl = client_ssl,
        remote_ssl = remote_ssl,
        client_session = nil,
        remote_session = nil,
        session_data = {},
        streams = {},
        host = host,
    }, M)
    
    local handler_handle = ffi.new_handle(self)

    local client_session_ptr = ffi.new("nghttp2_session*[1]")
    local client_session_data = ffi.new("nghttp2_session_data")
    client_session_data.handler = handler_handle
    client_session_data.client_ssl = client_ssl
    client_session_data.remote_ssl = remote_ssl
    client_session_data.host = host
    NGHTTP2.nghttp2_session_server_new(client_session_ptr, global_callbacks, client_session_data)
    self.client_session = ffi_gc(client_session_ptr[0], NGHTTP2.nghttp2_session_del)
    self.session_data[self.client_session] = client_session_data

    local remote_session_ptr = ffi.new("nghttp2_session*[1]")
    local remote_session_data = ffi.new("nghttp2_session_data")
    remote_session_data.handler = handler_handle
    remote_session_data.client_ssl = client_ssl
    remote_session_data.remote_ssl = remote_ssl
    remote_session_data.host = host
    NGHTTP2.nghttp2_session_client_new(remote_session_ptr, global_callbacks, remote_session_data)
    self.remote_session = ffi_gc(remote_session_ptr[0], NGHTTP2.nghttp2_session_del)
    self.session_data[self.remote_session] = remote_session_data

    self:send_settings(self.client_session)
    self:send_settings(self.remote_session)
    
    return self
end

function M:send_settings(session)
    local iv = ffi.new("nghttp2_settings_entry[2]")
    iv[0].settings_id = bindings.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS
    iv[0].value = 100
    iv[1].settings_id = bindings.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE
    iv[1].value = 65535
    NGHTTP2.nghttp2_submit_settings(session, bindings.NGHTTP2_FLAG_NONE, iv, 2)
end

function M:run_proxy_loop()
    local raw_sock1 = self.client_ssl:get_sock()
    local raw_sock2 = self.remote_ssl:get_sock()
    
    while true do
        local want_read1 = NGHTTP2.nghttp2_session_want_read(self.client_session)
        local want_write1 = NGHTTP2.nghttp2_session_want_write(self.client_session)
        local want_read2 = NGHTTP2.nghttp2_session_want_read(self.remote_session)
        local want_write2 = NGHTTP2.nghttp2_session_want_write(self.remote_session)
        
        if want_read1 == 0 and want_write1 == 0 and want_read2 == 0 and want_write2 == 0 then
            break
        end

        local read_fds = {}
        local write_fds = {}
        
        if want_read1 ~= 0 then read_fds[raw_sock1] = true end
        if want_write1 ~= 0 then write_fds[raw_sock1] = true end
        if want_read2 ~= 0 then read_fds[raw_sock2] = true end
        if want_write2 ~= 0 then write_fds[raw_sock2] = true end

        local read_tbl, write_tbl = {}, {}
        for k, _ in pairs(read_fds) do table.insert(read_tbl, k) end
        for k, _ in pairs(write_fds) do table.insert(write_tbl, k) end

        if #read_tbl == 0 and #write_tbl == 0 then
            break
        end

        local r, w, e = socket.select(
            #read_tbl > 0 and read_tbl or nil,
            #write_tbl > 0 and write_tbl or nil,
            TIMEOUT
        )
        
        if not r and not w and e == "timeout" then
            goto continue
        elseif not r and not w then
            return nil, "select error: " .. (e or "unknown")
        end
        
        local read_map, write_map = {}, {}
        for _, sock in ipairs(r or {}) do read_map[sock] = true end
        for _, sock in ipairs(w or {}) do write_map[sock] = true end
        
        if read_map[raw_sock1] or write_map[raw_sock1] then
            local ret = NGHTTP2.nghttp2_session_recv(self.client_session)
            if ret ~= 0 and ret ~= bindings.NGHTTP2_ERR_WOULDBLOCK then return nil, "client recv: " .. NGHTTP2.nghttp2_strerror(ret) end
            local ret = NGHTTP2.nghttp2_session_send(self.client_session)
            if ret ~= 0 and ret ~= bindings.NGHTTP2_ERR_WOULDBLOCK then return nil, "client send: " .. NGHTTP2.nghttp2_strerror(ret) end
        end
        
        if read_map[raw_sock2] or write_map[raw_sock2] then
             local ret = NGHTTP2.nghttp2_session_recv(self.remote_session)
            if ret ~= 0 and ret ~= bindings.NGHTTP2_ERR_WOULDBLOCK then return nil, "remote recv: " .. NGHTTP2.nghttp2_strerror(ret) end
            local ret = NGHTTP2.nghttp2_session_send(self.remote_session)
            if ret ~= 0 and ret ~= bindings.NGHTTP2_ERR_WOULDBLOCK then return nil, "remote send: " .. NGHTTP2.nghttp2_strerror(ret) end
        end
        
        ::continue::
    end
    
    return true
end

return M