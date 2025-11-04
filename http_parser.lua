local M = {}

function M.parse_http11_request(raw_request)
    local headers = {}
    
    local request_line_end = raw_request:find("\r?\n", 1, true)
    if not request_line_end then return nil, "Incomplete request line" end
    local request_line = raw_request:sub(1, request_line_end - 1)
    
    local method, url, proto = request_line:match("^(%S+) (%S+) (HTTP/1%.%d)\r?$")
    
    if not method then return nil, "Invalid request line: " .. request_line end
    
    local headers_end = raw_request:find("\r\n\r\n", request_line_end + 1)
    if not headers_end then 
        return nil, "Incomplete headers" 
    end
    
    local header_section = raw_request:sub(request_line_end + 1, headers_end + 1)
    
    local host
    for line in header_section:gmatch("([^\r\n]*)\r?\n") do
        if line == "" then break end
        local k, v = line:match("^([^:]+):%s*(.*)$")
        if k then
            local key_lower = k:lower()
            headers[key_lower] = v
            if key_lower == "host" then
                host = v:match("^[ \t]*(.-)[ \t]*$")
            end
        end
    end
    
    local body_start = headers_end + 4
    local body
    local content_length = tonumber(headers["content-length"] or "0")
    
    if content_length > 0 then
        body = raw_request:sub(body_start, body_start + content_length - 1)
    elseif method ~= "CONNECT" and #raw_request > body_start - 1 then
        body = raw_request:sub(body_start)
    end
    
    return {
        method = method,
        url = url,
        proto = proto,
        headers = headers,
        body = body,
        host = host or (method == "CONNECT" and url)
    }, nil, body_start
end

function M.parse_http11_response_headers(header_section)
    local headers = {}
    local status_code = 0
    local status_text = ""
    
    local request_line_end = header_section:find("\r?\n", 1, true)
    if not request_line_end then return 0, {} end
    
    local response_line = header_section:sub(1, request_line_end - 1)
    status_code, status_text = response_line:match("^HTTP/1%.%d (%d+) (.*)\r?$")
    status_code = tonumber(status_code) or 0
    
    for line in header_section:gmatch("([^\r\n]*)\r?\n") do
        if line == "" then break end
        local k, v = line:match("^([^:]+):%s*(.*)$")
        if k then
            headers[k:lower()] = v:match("^[ \t]*(.-)[ \t]*$")
        end
    end
    
    return status_code, headers
end

function M.build_http11_response(status_code, status_text, headers, body)
    local response_line = "HTTP/1.1 " .. status_code .. " " .. (status_text or "OK") .. "\r\n"
    local header_lines = {}
    
    local has_content_length = false
    for k, v in pairs(headers) do
        table.insert(header_lines, k .. ": " .. v .. "\r\n")
        if k:lower() == "content-length" then has_content_length = true end
    end
    
    if body and #body > 0 and not has_content_length then
        table.insert(header_lines, "Content-Length: " .. #body .. "\r\n")
    elseif not body and not has_content_length and status_code ~= 204 and status_code ~= 304 then
         table.insert(header_lines, "Content-Length: 0\r\n")
    end
    
    return response_line .. table.concat(header_lines) .. "\r\n" .. (body or "")
end

function M.headers_to_h2_nva(method, url, h11_headers)
    local nva = {}
    
    local host_header = h11_headers["host"] or ""
    local scheme = "https"
    
    local path = url
    local authority = host_header

    if url:sub(1, 4) == "http" then
        local s, a, p = url:match("^(https?)://([^/]+)(.*)$")
        if s then
            scheme, authority, path = s, a, p
            path = path == "" and "/" or path
        else
            path = "/"
        end
    else
        local s, a, p = url:match("^(https?)://([^/]+)(.*)$")
         if s then
            scheme, authority, path = s, a, p
            path = path == "" and "/" or path
        end
    end
    
    if method == "CONNECT" then
        authority = url
        path = nil
        scheme = nil
    end

    table.insert(nva, { name = ":method", value = method })
    if path then table.insert(nva, { name = ":path", value = path }) end
    if scheme then table.insert(nva, { name = ":scheme", value = scheme }) end
    if authority then table.insert(nva, { name = ":authority", value = authority }) end
    
    for k, v in pairs(h11_headers) do
        local key_lower = k:lower()
        if key_lower ~= "host" and key_lower ~= "connection" and key_lower ~= "proxy-connection" and key_lower ~= "keep-alive" and key_lower ~= "transfer-encoding" and key_lower ~= "upgrade" then
            table.insert(nva, { name = key_lower, value = v })
        end
    end
    
    return nva
end

function M.h2_headers_to_h11_response(nva)
    local headers = {}
    local status = "200"
    
    for _, nv in ipairs(nva) do
        if nv.name == ":status" then
            status = nv.value
        elseif nv.name:sub(1, 1) ~= ":" then
            headers[nv.name] = nv.value
        end
    end
    
    return tonumber(status), headers
end

return M