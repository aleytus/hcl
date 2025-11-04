local ffi = require('ffi')

ffi.cdef [[
struct nghttp2_session;
typedef struct nghttp2_session nghttp2_session;
typedef struct nghttp2_info {
  int age;
  int version_num;
  const char *version_str;
  const char *proto_str;
} nghttp2_info;
typedef enum nghttp2_error {
  NGHTTP2_ERR_INVALID_ARGUMENT = -501,
  NGHTTP2_ERR_BUFFER_ERROR = -502,
  NGHTTP2_ERR_UNSUPPORTED_VERSION = -503,
  NGHTTP2_ERR_WOULDBLOCK = -504,
  NGHTTP2_ERR_PROTO = -505,
  NGHTTP2_ERR_INVALID_FRAME = -506,
  NGHTTP2_ERR_EOF = -507,
  NGHTTP2_ERR_DEFERRED = -508,
  NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE = -509,
  NGHTTP2_ERR_STREAM_CLOSED = -510,
  NGHTTP2_ERR_STREAM_CLOSING = -511,
  NGHTTP2_ERR_STREAM_SHUT_WR = -512,
  NGHTTP2_ERR_INVALID_STREAM_ID = -513,
  NGHTTP2_ERR_INVALID_STREAM_STATE = -514,
  NGHTTP2_ERR_DEFERRED_DATA_EXIST = -515,
  NGHTTP2_ERR_START_STREAM_NOT_ALLOWED = -516,
  NGHTTP2_ERR_GOAWAY_ALREADY_SENT = -517,
  NGHTTP2_ERR_INVALID_HEADER_BLOCK = -518,
  NGHTTP2_ERR_INVALID_STATE = -519,
  NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE = -521,
  NGHTTP2_ERR_FRAME_SIZE_ERROR = -522,
  NGHTTP2_ERR_HEADER_COMP = -523,
  NGHTTP2_ERR_FLOW_CONTROL = -524,
  NGHTTP2_ERR_INSUFF_BUFSIZE = -525,
  NGHTTP2_ERR_PAUSE = -526,
  NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS = -527,
  NGHTTP2_ERR_PUSH_DISABLED = -528,
  NGHTTP2_ERR_DATA_EXIST = -529,
  NGHTTP2_ERR_SESSION_CLOSING = -530,
  NGHTTP2_ERR_HTTP_HEADER = -531,
  NGHTTP2_ERR_HTTP_MESSAGING = -532,
  NGHTTP2_ERR_REFUSED_STREAM = -533,
  NGHTTP2_ERR_INTERNAL = -534,
  NGHTTP2_ERR_CANCEL = -535,
  NGHTTP2_ERR_SETTINGS_EXPECTED = -536,
  NGHTTP2_ERR_TOO_MANY_SETTINGS = -537,
  NGHTTP2_ERR_FATAL = -900,
  NGHTTP2_ERR_NOMEM = -901,
  NGHTTP2_ERR_CALLBACK_FAILURE = -902,
  NGHTTP2_ERR_BAD_CLIENT_MAGIC = -903,
  NGHTTP2_ERR_FLOODED = -904
} nghttp2_error;
typedef struct nghttp2_vec {
  uint8_t *base;
  size_t len;
} nghttp2_vec;
struct nghttp2_rcbuf;
typedef struct nghttp2_rcbuf nghttp2_rcbuf;
void nghttp2_rcbuf_incref(nghttp2_rcbuf *rcbuf);
void nghttp2_rcbuf_decref(nghttp2_rcbuf *rcbuf);
nghttp2_vec nghttp2_rcbuf_get_buf(nghttp2_rcbuf *rcbuf);
int nghttp2_rcbuf_is_static(const nghttp2_rcbuf *rcbuf);
typedef enum nghttp2_nv_flag {
  NGHTTP2_NV_FLAG_NONE = 0,
  NGHTTP2_NV_FLAG_NO_INDEX = 0x01,
  NGHTTP2_NV_FLAG_NO_COPY_NAME = 0x02,
  NGHTTP2_NV_FLAG_NO_COPY_VALUE = 0x04
} nghttp2_nv_flag;
typedef struct nghttp2_nv {
  const int8_t *name;
  const int8_t *value;
  size_t namelen;
  size_t valuelen;
  uint8_t flags;
} nghttp2_nv;
typedef enum nghttp2_frame_type {
  NGHTTP2_DATA = 0,
  NGHTTP2_HEADERS = 0x01,
  NGHTTP2_PRIORITY = 0x02,
  NGHTTP2_RST_STREAM = 0x03,
  NGHTTP2_SETTINGS = 0x04,
  NGHTTP2_PUSH_PROMISE = 0x05,
  NGHTTP2_PING = 0x06,
  NGHTTP2_GOAWAY = 0x07,
  NGHTTP2_WINDOW_UPDATE = 0x08,
  NGHTTP2_CONTINUATION = 0x09,
  NGHTTP2_ALTSVC = 0x0a,
  NGHTTP2_ORIGIN = 0x0c,
  NGHTTP2_PRIORITY_UPDATE = 0x10
} nghttp2_frame_type;
typedef enum nghttp2_flag {
  NGHTTP2_FLAG_NONE = 0,
  NGHTTP2_FLAG_END_STREAM = 0x01,
  NGHTTP2_FLAG_END_HEADERS = 0x04,
  NGHTTP2_FLAG_ACK = 0x01,
  NGHTTP2_FLAG_PADDED = 0x08,
  NGHTTP2_FLAG_PRIORITY = 0x20
} nghttp2_flag;
typedef enum nghttp2_settings_id {
  NGHTTP2_SETTINGS_HEADER_TABLE_SIZE = 0x01,
  NGHTTP2_SETTINGS_ENABLE_PUSH = 0x02,
  NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x03,
  NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 0x04,
  NGHTTP2_SETTINGS_MAX_FRAME_SIZE = 0x05,
  NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x06,
  NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08,
  NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES = 0x09
} nghttp2_settings_id;
typedef enum nghttp2_error_code {
  NGHTTP2_NO_ERROR = 0x00,
  NGHTTP2_PROTOCOL_ERROR = 0x01,
  NGHTTP2_INTERNAL_ERROR = 0x02,
  NGHTTP2_FLOW_CONTROL_ERROR = 0x03,
  NGHTTP2_SETTINGS_TIMEOUT = 0x04,
  NGHTTP2_STREAM_CLOSED = 0x05,
  NGHTTP2_FRAME_SIZE_ERROR = 0x06,
  NGHTTP2_REFUSED_STREAM = 0x07,
  NGHTTP2_CANCEL = 0x08,
  NGHTTP2_COMPRESSION_ERROR = 0x09,
  NGHTTP2_CONNECT_ERROR = 0x0a,
  NGHTTP2_ENHANCE_YOUR_CALM = 0x0b,
  NGHTTP2_INADEQUATE_SECURITY = 0x0c,
  NGHTTP2_HTTP_1_1_REQUIRED = 0x0d
} nghttp2_error_code;
typedef struct nghttp2_frame_hd {
  size_t length;
  int32_t stream_id;
  uint8_t type;
  uint8_t flags;
  uint8_t reserved;
} nghttp2_frame_hd;
typedef union nghttp2_data_source {
  int fd;
  void *ptr;
} nghttp2_data_source;
typedef enum nghttp2_data_flag {
  NGHTTP2_DATA_FLAG_NONE = 0,
  NGHTTP2_DATA_FLAG_EOF = 0x01,
  NGHTTP2_DATA_FLAG_NO_END_STREAM = 0x02,
  NGHTTP2_DATA_FLAG_NO_COPY = 0x04
} nghttp2_data_flag;
typedef ssize_t (*nghttp2_data_source_read_callback)(
    nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
    uint32_t *data_flags, nghttp2_data_source *source, void *user_data);
typedef struct nghttp2_data_provider {
  nghttp2_data_source source;
  nghttp2_data_source_read_callback read_callback;
} nghttp2_data_provider;
typedef struct nghttp2_data {
  nghttp2_frame_hd hd;
  size_t padlen;
} nghttp2_data;
typedef enum nghttp2_headers_category {
  NGHTTP2_HCAT_REQUEST = 0,
  NGHTTP2_HCAT_RESPONSE = 1,
  NGHTTP2_HCAT_PUSH_RESPONSE = 2,
  NGHTTP2_HCAT_HEADERS = 3
} nghttp2_headers_category;
typedef struct nghttp2_priority_spec {
  int32_t stream_id;
  int32_t weight;
  uint8_t exclusive;
} nghttp2_priority_spec;
typedef struct nghttp2_headers {
  nghttp2_frame_hd hd;
  size_t padlen;
  nghttp2_priority_spec pri_spec;
  nghttp2_nv *nva;
  size_t nvlen;
  nghttp2_headers_category cat;
} nghttp2_headers;
typedef struct nghttp2_priority {
  nghttp2_frame_hd hd;
  nghttp2_priority_spec pri_spec;
} nghttp2_priority;
typedef struct nghttp2_rst_stream {
  nghttp2_frame_hd hd;
  uint32_t error_code;
} nghttp2_rst_stream;
typedef struct nghttp2_settings_entry {
  int32_t settings_id;
  uint32_t value;
} nghttp2_settings_entry;
typedef struct nghttp2_settings {
  nghttp2_frame_hd hd;
  size_t niv;
  nghttp2_settings_entry *iv;
} nghttp2_settings;
typedef struct nghttp2_push_promise {
  nghttp2_frame_hd hd;
  size_t padlen;
  nghttp2_nv *nva;
  size_t nvlen;
  int32_t promised_stream_id;
  uint8_t reserved;
} nghttp2_push_promise;
typedef struct nghttp2_ping {
  nghttp2_frame_hd hd;
  uint8_t opaque_data[8];
} nghttp2_ping;
typedef struct nghttp2_goaway {
  nghttp2_frame_hd hd;
  int32_t last_stream_id;
  uint32_t error_code;
  uint8_t *opaque_data;
  size_t opaque_data_len;
  uint8_t reserved;
} nghttp2_goaway;
typedef struct nghttp2_window_update {
  nghttp2_frame_hd hd;
  int32_t window_size_increment;
  uint8_t reserved;
} nghttp2_window_update;
typedef struct nghttp2_extension {
  nghttp2_frame_hd hd;
  void *payload;
} nghttp2_extension;
typedef union nghttp2_frame {
  nghttp2_frame_hd hd;
  nghttp2_data data;
  nghttp2_headers headers;
  nghttp2_priority priority;
  nghttp2_rst_stream rst_stream;
  nghttp2_settings settings;
  nghttp2_push_promise push_promise;
  nghttp2_ping ping;
  nghttp2_goaway goaway;
  nghttp2_window_update window_update;
  nghttp2_extension ext;
} nghttp2_frame;
typedef ssize_t (*nghttp2_send_callback)(nghttp2_session *session,
                                         const uint8_t *data, size_t length,
                                         int flags, void *user_data);
typedef int (*nghttp2_send_data_callback)(nghttp2_session *session,
                                          nghttp2_frame *frame,
                                          const uint8_t *framehd, size_t length,
                                          nghttp2_data_source *source,
                                          void *user_data);
typedef ssize_t (*nghttp2_recv_callback)(nghttp2_session *session, uint8_t *buf,
                                         size_t length, int flags,
                                         void *user_data);
typedef int (*nghttp2_on_frame_recv_callback)(nghttp2_session *session,
                                              const nghttp2_frame *frame,
                                              void *user_data);
typedef int (*nghttp2_on_invalid_frame_recv_callback)(
    nghttp2_session *session, const nghttp2_frame *frame, int lib_error_code,
    void *user_data);
typedef int (*nghttp2_on_data_chunk_recv_callback)(nghttp2_session *session,
                                                   uint8_t flags,
                                                   int32_t stream_id,
                                                   const uint8_t *data,
                                                   size_t len, void *user_data);
typedef int (*nghttp2_before_frame_send_callback)(nghttp2_session *session,
                                                  const nghttp2_frame *frame,
                                                  void *user_data);
typedef int (*nghttp2_on_frame_send_callback)(nghttp2_session *session,
                                              const nghttp2_frame *frame,
                                              void *user_data);
typedef int (*nghttp2_on_frame_not_send_callback)(nghttp2_session *session,
                                                  const nghttp2_frame *frame,
                                                  int lib_error_code,
                                                  void *user_data);
typedef int (*nghttp2_on_stream_close_callback)(nghttp2_session *session,
                                                int32_t stream_id,
                                                uint32_t error_code,
                                                void *user_data);
typedef int (*nghttp2_on_begin_headers_callback)(nghttp2_session *session,
                                                 const nghttp2_frame *frame,
                                                 void *user_data);
typedef int (*nghttp2_on_header_callback)(nghttp2_session *session,
                                          const nghttp2_frame *frame,
                                          const uint8_t *name, size_t namelen,
                                          const uint8_t *value, size_t valuelen,
                                          uint8_t flags, void *user_data);
typedef int (*nghttp2_on_header_callback2)(nghttp2_session *session,
                                           const nghttp2_frame *frame,
                                           nghttp2_rcbuf *name,
                                           nghttp2_rcbuf *value, uint8_t flags,
                                           void *user_data);
typedef int (*nghttp2_on_invalid_header_callback)(
    nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
    size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
    void *user_data);
typedef int (*nghttp2_on_invalid_header_callback2)(
    nghttp2_session *session, const nghttp2_frame *frame, nghttp2_rcbuf *name,
    nghttp2_rcbuf *value, uint8_t flags, void *user_data);
typedef ssize_t (*nghttp2_select_padding_callback)(nghttp2_session *session,
                                                   const nghttp2_frame *frame,
                                                   size_t max_payloadlen,
                                                   void *user_data);
typedef ssize_t (*nghttp2_data_source_read_length_callback)(
    nghttp2_session *session, uint8_t frame_type, int32_t stream_id,
    int32_t session_remote_window_size, int32_t stream_remote_window_size,
    uint32_t remote_max_frame_size, void *user_data);
typedef int (*nghttp2_on_begin_frame_callback)(nghttp2_session *session,
                                               const nghttp2_frame_hd *hd,
                                               void *user_data);
typedef int (*nghttp2_on_extension_chunk_recv_callback)(
    nghttp2_session *session, const nghttp2_frame_hd *hd, const uint8_t *data,
    size_t len, void *user_data);
typedef int (*nghttp2_unpack_extension_callback)(nghttp2_session *session,
                                                 void **payload,
                                                 const nghttp2_frame_hd *hd,
                                                 void *user_data);
typedef ssize_t (*nghttp2_pack_extension_callback)(nghttp2_session *session,
                                                   uint8_t *buf, size_t len,
                                                   const nghttp2_frame *frame,
                                                   void *user_data);
typedef int (*nghttp2_error_callback)(nghttp2_session *session, const char *msg,
                                      size_t len, void *user_data);
typedef int (*nghttp2_error_callback2)(nghttp2_session *session,
                                       int lib_error_code, const char *msg,
                                       size_t len, void *user_data);
struct nghttp2_session_callbacks;
typedef struct nghttp2_session_callbacks nghttp2_session_callbacks;
int nghttp2_session_callbacks_new(nghttp2_session_callbacks **callbacks_ptr);
void nghttp2_session_callbacks_del(nghttp2_session_callbacks *callbacks);
void nghttp2_session_callbacks_set_send_callback(
    nghttp2_session_callbacks *cbs, nghttp2_send_callback send_callback);
void nghttp2_session_callbacks_set_recv_callback(
    nghttp2_session_callbacks *cbs, nghttp2_recv_callback recv_callback);
void nghttp2_session_callbacks_set_on_frame_recv_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_frame_recv_callback on_frame_recv_callback);
void nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_invalid_frame_recv_callback on_invalid_frame_recv_callback);
void nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_data_chunk_recv_callback on_data_chunk_recv_callback);
void nghttp2_session_callbacks_set_before_frame_send_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_before_frame_send_callback before_frame_send_callback);
void nghttp2_session_callbacks_set_on_frame_send_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_frame_send_callback on_frame_send_callback);
void nghttp2_session_callbacks_set_on_frame_not_send_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_frame_not_send_callback on_frame_not_send_callback);
void nghttp2_session_callbacks_set_on_stream_close_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_stream_close_callback on_stream_close_callback);
void nghttp2_session_callbacks_set_on_begin_headers_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_begin_headers_callback on_begin_headers_callback);
void nghttp2_session_callbacks_set_on_header_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_header_callback on_header_callback);
void nghttp2_session_callbacks_set_on_header_callback2(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_header_callback2 on_header_callback2);
void nghttp2_session_callbacks_set_on_invalid_header_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_invalid_header_callback on_invalid_header_callback);
void nghttp2_session_callbacks_set_on_invalid_header_callback2(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_invalid_header_callback2 on_invalid_header_callback2);
void nghttp2_session_callbacks_set_select_padding_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_select_padding_callback select_padding_callback);
void nghttp2_session_callbacks_set_data_source_read_length_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_data_source_read_length_callback data_source_read_length_callback);
void nghttp2_session_callbacks_set_on_begin_frame_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_begin_frame_callback on_begin_frame_callback);
void nghttp2_session_callbacks_set_send_data_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_send_data_callback send_data_callback);
void nghttp2_session_callbacks_set_pack_extension_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_pack_extension_callback pack_extension_callback);
void nghttp2_session_callbacks_set_unpack_extension_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_unpack_extension_callback unpack_extension_callback);
void nghttp2_session_callbacks_set_on_extension_chunk_recv_callback(
    nghttp2_session_callbacks *cbs,
    nghttp2_on_extension_chunk_recv_callback on_extension_chunk_recv_callback);
void nghttp2_session_callbacks_set_error_callback(
    nghttp2_session_callbacks *cbs, nghttp2_error_callback error_callback);
void nghttp2_session_callbacks_set_error_callback2(
    nghttp2_session_callbacks *cbs, nghttp2_error_callback2 error_callback2);
typedef void *(*nghttp2_malloc)(size_t size, void *mem_user_data);
typedef void (*nghttp2_free)(void *ptr, void *mem_user_data);
typedef void *(*nghttp2_calloc)(size_t nmemb, size_t size, void *mem_user_data);
typedef void *(*nghttp2_realloc)(void *ptr, size_t size, void *mem_user_data);
typedef struct nghttp2_mem {
  void *mem_user_data;
  nghttp2_malloc malloc;
  nghttp2_free free;
  nghttp2_calloc calloc;
  nghttp2_realloc realloc;
} nghttp2_mem;
struct nghttp2_option;
typedef struct nghttp2_option nghttp2_option;
int nghttp2_option_new(nghttp2_option **option_ptr);
void nghttp2_option_del(nghttp2_option *option);
void nghttp2_option_set_no_auto_window_update(nghttp2_option *option, int val);
void nghttp2_option_set_peer_max_concurrent_streams(nghttp2_option *option,
                                                    uint32_t val);
void nghttp2_option_set_no_recv_client_magic(nghttp2_option *option, int val);
void nghttp2_option_set_no_http_messaging(nghttp2_option *option, int val);
void nghttp2_option_set_max_reserved_remote_streams(nghttp2_option *option,
                                                    uint32_t val);
void nghttp2_option_set_user_recv_extension_type(nghttp2_option *option,
                                                 uint8_t type);
void nghttp2_option_set_builtin_recv_extension_type(nghttp2_option *option,
                                                    uint8_t type);
void nghttp2_option_set_no_auto_ping_ack(nghttp2_option *option, int val);
void nghttp2_option_set_max_send_header_block_length(nghttp2_option *option,
                                                     size_t val);
void nghttp2_option_set_max_deflate_dynamic_table_size(nghttp2_option *option,
                                                       size_t val);
void nghttp2_option_set_no_closed_streams(nghttp2_option *option, int val);
void nghttp2_option_set_max_outbound_ack(nghttp2_option *option, size_t val);
void nghttp2_option_set_max_settings(nghttp2_option *option, size_t val);
void nghttp2_option_set_server_fallback_rfc7540_priorities(
    nghttp2_option *option, int val);
void nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation(
    nghttp2_option *option, int val);
int nghttp2_session_client_new(nghttp2_session **session_ptr,
                               const nghttp2_session_callbacks *callbacks,
                               void *user_data);
int nghttp2_session_server_new(nghttp2_session **session_ptr,
                               const nghttp2_session_callbacks *callbacks,
                               void *user_data);
int nghttp2_session_client_new2(nghttp2_session **session_ptr,
                                const nghttp2_session_callbacks *callbacks,
                                void *user_data, const nghttp2_option *option);
int nghttp2_session_server_new2(nghttp2_session **session_ptr,
                                const nghttp2_session_callbacks *callbacks,
                                void *user_data, const nghttp2_option *option);
int nghttp2_session_client_new3(nghttp2_session **session_ptr,
                                const nghttp2_session_callbacks *callbacks,
                                void *user_data, const nghttp2_option *option,
                                nghttp2_mem *mem);
int nghttp2_session_server_new3(nghttp2_session **session_ptr,
                                const nghttp2_session_callbacks *callbacks,
                                void *user_data, const nghttp2_option *option,
                                nghttp2_mem *mem);
void nghttp2_session_del(nghttp2_session *session);
int nghttp2_session_send(nghttp2_session *session);
ssize_t nghttp2_session_mem_send(nghttp2_session *session,
                                 const uint8_t **data_ptr);
int nghttp2_session_recv(nghttp2_session *session);
ssize_t nghttp2_session_mem_recv(nghttp2_session *session, const uint8_t *in,
                                 size_t inlen);
int nghttp2_session_resume_data(nghttp2_session *session, int32_t stream_id);
int nghttp2_session_want_read(nghttp2_session *session);
int nghttp2_session_want_write(nghttp2_session *session);
void *nghttp2_session_get_stream_user_data(nghttp2_session *session,
                                           int32_t stream_id);
int nghttp2_session_set_stream_user_data(nghttp2_session *session,
                                         int32_t stream_id,
                                         void *stream_user_data);
void nghttp2_session_set_user_data(nghttp2_session *session, void *user_data);
size_t nghttp2_session_get_outbound_queue_size(nghttp2_session *session);
int32_t
nghttp2_session_get_stream_effective_recv_data_length(nghttp2_session *session,
                                                      int32_t stream_id);
int32_t
nghttp2_session_get_stream_effective_local_window_size(nghttp2_session *session,
                                                       int32_t stream_id);
int32_t nghttp2_session_get_stream_local_window_size(nghttp2_session *session,
                                                     int32_t stream_id);
int32_t
nghttp2_session_get_effective_recv_data_length(nghttp2_session *session);
int32_t
nghttp2_session_get_effective_local_window_size(nghttp2_session *session);
int32_t nghttp2_session_get_local_window_size(nghttp2_session *session);
int32_t nghttp2_session_get_stream_remote_window_size(nghttp2_session *session,
                                                      int32_t stream_id);
int32_t nghttp2_session_get_remote_window_size(nghttp2_session *session);
int nghttp2_session_get_stream_local_close(nghttp2_session *session,
                                           int32_t stream_id);
int nghttp2_session_get_stream_remote_close(nghttp2_session *session,
                                            int32_t stream_id);
size_t
nghttp2_session_get_hd_inflate_dynamic_table_size(nghttp2_session *session);
size_t
nghttp2_session_get_hd_deflate_dynamic_table_size(nghttp2_session *session);
int nghttp2_session_terminate_session(nghttp2_session *session,
                                      uint32_t error_code);
int nghttp2_session_terminate_session2(nghttp2_session *session,
                                       int32_t last_stream_id,
                                       uint32_t error_code);
int nghttp2_submit_shutdown_notice(nghttp2_session *session);
uint32_t nghttp2_session_get_remote_settings(nghttp2_session *session,
                                             nghttp2_settings_id id);
uint32_t nghttp2_session_get_local_settings(nghttp2_session *session,
                                            nghttp2_settings_id id);
int nghttp2_session_set_next_stream_id(nghttp2_session *session,
                                       int32_t next_stream_id);
uint32_t nghttp2_session_get_next_stream_id(nghttp2_session *session);
int nghttp2_session_consume(nghttp2_session *session, int32_t stream_id,
                            size_t size);
int nghttp2_session_consume_connection(nghttp2_session *session, size_t size);
int nghttp2_session_consume_stream(nghttp2_session *session, int32_t stream_id,
                                   size_t size);
int nghttp2_session_change_stream_priority(
    nghttp2_session *session, int32_t stream_id,
    const nghttp2_priority_spec *pri_spec);
int nghttp2_session_create_idle_stream(nghttp2_session *session,
                                       int32_t stream_id,
                                       const nghttp2_priority_spec *pri_spec);
int nghttp2_session_upgrade(nghttp2_session *session,
                            const uint8_t *settings_payload,
                            size_t settings_payloadlen, void *stream_user_data);
int nghttp2_session_upgrade2(nghttp2_session *session,
                             const uint8_t *settings_payload,
                             size_t settings_payloadlen, int head_request,
                             void *stream_user_data);
ssize_t nghttp2_pack_settings_payload(uint8_t *buf, size_t buflen,
                                      const nghttp2_settings_entry *iv,
                                      size_t niv);
const char *nghttp2_strerror(int lib_error_code);
const char *nghttp2_http2_strerror(uint32_t error_code);
void nghttp2_priority_spec_init(nghttp2_priority_spec *pri_spec,
                                int32_t stream_id, int32_t weight,
                                int exclusive);
void nghttp2_priority_spec_default_init(nghttp2_priority_spec *pri_spec);
int nghttp2_priority_spec_check_default(const nghttp2_priority_spec *pri_spec);
int32_t nghttp2_submit_request(nghttp2_session *session,
                               const nghttp2_priority_spec *pri_spec,
                               const nghttp2_nv *nva, size_t nvlen,
                               const nghttp2_data_provider *data_prd,
                               void *stream_user_data);
int nghttp2_submit_response(nghttp2_session *session, int32_t stream_id,
                            const nghttp2_nv *nva, size_t nvlen,
                            const nghttp2_data_provider *data_prd);
int nghttp2_submit_trailer(nghttp2_session *session, int32_t stream_id,
                           const nghttp2_nv *nva, size_t nvlen);
int32_t nghttp2_submit_headers(nghttp2_session *session, uint8_t flags,
                               int32_t stream_id,
                               const nghttp2_priority_spec *pri_spec,
                               const nghttp2_nv *nva, size_t nvlen,
                               void *stream_user_data);
int nghttp2_submit_data(nghttp2_session *session, uint8_t flags,
                        int32_t stream_id,
                        const nghttp2_data_provider *data_prd);
int nghttp2_submit_priority(nghttp2_session *session, uint8_t flags,
                            int32_t stream_id,
                            const nghttp2_priority_spec *pri_spec);
typedef struct nghttp2_extpri {
  uint32_t urgency;
  int inc;
} nghttp2_extpri;
int nghttp2_submit_rst_stream(nghttp2_session *session, uint8_t flags,
                              int32_t stream_id, uint32_t error_code);
int nghttp2_submit_settings(nghttp2_session *session, uint8_t flags,
                            const nghttp2_settings_entry *iv, size_t niv);
int32_t nghttp2_submit_push_promise(nghttp2_session *session, uint8_t flags,
                                    int32_t stream_id, const nghttp2_nv *nva,
                                    size_t nvlen,
                                    void *promised_stream_user_data);
int nghttp2_submit_ping(nghttp2_session *session, uint8_t flags,
                        const uint8_t *opaque_data);
int nghttp2_submit_goaway(nghttp2_session *session, uint8_t flags,
                          int32_t last_stream_id, uint32_t error_code,
                          const uint8_t *opaque_data, size_t opaque_data_len);
int32_t nghttp2_session_get_last_proc_stream_id(nghttp2_session *session);
int nghttp2_session_check_request_allowed(nghttp2_session *session);
int nghttp2_session_check_server_session(nghttp2_session *session);
int nghttp2_submit_window_update(nghttp2_session *session, uint8_t flags,
                                 int32_t stream_id,
                                 int32_t window_size_increment);
int nghttp2_session_set_local_window_size(nghttp2_session *session,
                                          uint8_t flags, int32_t stream_id,
                                          int32_t window_size);
int nghttp2_submit_extension(nghttp2_session *session, uint8_t type,
                             uint8_t flags, int32_t stream_id, void *payload);
typedef struct nghttp2_ext_altsvc {
  uint8_t *origin;
  size_t origin_len;
  uint8_t *field_value;
  size_t field_value_len;
} nghttp2_ext_altsvc;
int nghttp2_submit_altsvc(nghttp2_session *session, uint8_t flags,
                          int32_t stream_id, const uint8_t *origin,
                          size_t origin_len, const uint8_t *field_value,
                          size_t field_value_len);
typedef struct nghttp2_origin_entry {
  uint8_t *origin;
  size_t origin_len;
} nghttp2_origin_entry;
typedef struct nghttp2_ext_origin {
  size_t nov;
  nghttp2_origin_entry *ov;
} nghttp2_ext_origin;
int nghttp2_submit_origin(nghttp2_session *session, uint8_t flags,
                          const nghttp2_origin_entry *ov, size_t nov);
typedef struct nghttp2_ext_priority_update {
  int32_t stream_id;
  uint8_t *field_value;
  size_t field_value_len;
} nghttp2_ext_priority_update;
int nghttp2_submit_priority_update(nghttp2_session *session, uint8_t flags,
                                   int32_t stream_id,
                                   const uint8_t *field_value,
                                   size_t field_value_len);
int nghttp2_session_change_extpri_stream_priority(nghttp2_session *session,
                                                  int32_t stream_id,
                                                  const nghttp2_extpri *extpri,
                                                  int ignore_client_signal);
int nghttp2_nv_compare_name(const nghttp2_nv *lhs, const nghttp2_nv *rhs);
int nghttp2_select_next_protocol(unsigned char **out, unsigned char *outlen,
                                 const unsigned char *in, unsigned int inlen);
nghttp2_info *nghttp2_version(int least_version);
int nghttp2_is_fatal(int lib_error_code);
int nghttp2_check_header_name(const uint8_t *name, size_t len);
int nghttp2_check_header_value(const uint8_t *value, size_t len);
int nghttp2_check_header_value_rfc9113(const uint8_t *value, size_t len);
int nghttp2_check_method(const uint8_t *value, size_t len);
int nghttp2_check_path(const uint8_t *value, size_t len);
int nghttp2_check_authority(const uint8_t *value, size_t len);
struct nghttp2_hd_deflater;
typedef struct nghttp2_hd_deflater nghttp2_hd_deflater;
int nghttp2_hd_deflate_new(nghttp2_hd_deflater **deflater_ptr,
                           size_t max_deflate_dynamic_table_size);
int nghttp2_hd_deflate_new2(nghttp2_hd_deflater **deflater_ptr,
                            size_t max_deflate_dynamic_table_size,
                            nghttp2_mem *mem);
void nghttp2_hd_deflate_del(nghttp2_hd_deflater *deflater);
int nghttp2_hd_deflate_change_table_size(
    nghttp2_hd_deflater *deflater, size_t settings_max_dynamic_table_size);
ssize_t nghttp2_hd_deflate_hd(nghttp2_hd_deflater *deflater, uint8_t *buf,
                              size_t buflen, const nghttp2_nv *nva,
                              size_t nvlen);
ssize_t nghttp2_hd_deflate_hd_vec(nghttp2_hd_deflater *deflater,
                                  const nghttp2_vec *vec, size_t veclen,
                                  const nghttp2_nv *nva, size_t nvlen);
size_t nghttp2_hd_deflate_bound(nghttp2_hd_deflater *deflater,
                                const nghttp2_nv *nva, size_t nvlen);
size_t nghttp2_hd_deflate_get_num_table_entries(nghttp2_hd_deflater *deflater);
const nghttp2_nv *
nghttp2_hd_deflate_get_table_entry(nghttp2_hd_deflater *deflater, size_t idx);
size_t nghttp2_hd_deflate_get_dynamic_table_size(nghttp2_hd_deflater *deflater);
size_t
nghttp2_hd_deflate_get_max_dynamic_table_size(nghttp2_hd_deflater *deflater);
struct nghttp2_hd_inflater;
typedef struct nghttp2_hd_inflater nghttp2_hd_inflater;
int nghttp2_hd_inflate_new(nghttp2_hd_inflater **inflater_ptr);
int nghttp2_hd_inflate_new2(nghttp2_hd_inflater **inflater_ptr,
                            nghttp2_mem *mem);
void nghttp2_hd_inflate_del(nghttp2_hd_inflater *inflater);
int nghttp2_hd_inflate_change_table_size(
    nghttp2_hd_inflater *inflater, size_t settings_max_dynamic_table_size);
typedef enum nghttp2_hd_inflate_flag {
  NGHTTP2_HD_INFLATE_NONE = 0,
  NGHTTP2_HD_INFLATE_FINAL = 0x01,
  NGHTTP2_HD_INFLATE_EMIT = 0x02
} nghttp2_hd_inflate_flag;
ssize_t nghttp2_hd_inflate_hd(nghttp2_hd_inflater *inflater, nghttp2_nv *nv_out,
                              int *inflate_flags, uint8_t *in, size_t inlen,
                              int in_final);
ssize_t nghttp2_hd_inflate_hd2(nghttp2_hd_inflater *inflater,
                               nghttp2_nv *nv_out, int *inflate_flags,
                               const uint8_t *in, size_t inlen, int in_final);
int nghttp2_hd_inflate_end_headers(nghttp2_hd_inflater *inflater);
size_t nghttp2_hd_inflate_get_num_table_entries(nghttp2_hd_inflater *inflater);
const nghttp2_nv *
nghttp2_hd_inflate_get_table_entry(nghttp2_hd_inflater *inflater, size_t idx);
size_t nghttp2_hd_inflate_get_dynamic_table_size(nghttp2_hd_inflater *inflater);
size_t
nghttp2_hd_inflate_get_max_dynamic_table_size(nghttp2_hd_inflater *inflater);
struct nghttp2_stream;
typedef struct nghttp2_stream nghttp2_stream;
nghttp2_stream *nghttp2_session_find_stream(nghttp2_session *session,
                                            int32_t stream_id);
typedef enum nghttp2_stream_proto_state {
  NGHTTP2_STREAM_STATE_IDLE = 1,
  NGHTTP2_STREAM_STATE_OPEN,
  NGHTTP2_STREAM_STATE_RESERVED_LOCAL,
  NGHTTP2_STREAM_STATE_RESERVED_REMOTE,
  NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL,
  NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE,
  NGHTTP2_STREAM_STATE_CLOSED
} nghttp2_stream_proto_state;
nghttp2_stream_proto_state nghttp2_stream_get_state(nghttp2_stream *stream);
nghttp2_stream *nghttp2_session_get_root_stream(nghttp2_session *session);
nghttp2_stream *nghttp2_stream_get_parent(nghttp2_stream *stream);
int32_t nghttp2_stream_get_stream_id(nghttp2_stream *stream);
nghttp2_stream *nghttp2_stream_get_next_sibling(nghttp2_stream *stream);
nghttp2_stream *nghttp2_stream_get_previous_sibling(nghttp2_stream *stream);
nghttp2_stream *nghttp2_stream_get_first_child(nghttp2_stream *stream);
int32_t nghttp2_stream_get_weight(nghttp2_stream *stream);
int32_t nghttp2_stream_get_sum_dependency_weight(nghttp2_stream *stream);
typedef void (*nghttp2_debug_vprintf_callback)(const char *format,
                                               va_list args);
void nghttp2_set_debug_vprintf_callback(
    nghttp2_debug_vprintf_callback debug_vprintf_callback);
]]
