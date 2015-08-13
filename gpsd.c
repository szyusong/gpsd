
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <gio/gio.h>
#include <zmq.h>
#include <czmq.h>
#include <zlog.h>
#include <sqlite3.h>

#include "pt.h"
#include "utils.h"

#define GPSD_CONFIG_FILE "/etc/gpsd/gpsd.conf"
#define GPSD_DEFAULT_PORT 1391

// 命令行参数
static gboolean run_as_daemon = FALSE;
static gboolean kill_daemon = FALSE;
static gint logger_port = 0;

static GOptionEntry cmd_entries[] =
{
  {"daemon", 'd', 0, G_OPTION_ARG_NONE, &run_as_daemon, "Run as daemon", NULL},
  {"kill", 'k', 0, G_OPTION_ARG_NONE, &kill_daemon, "Kill daemon", NULL},
  {"logger", 'l', 0, G_OPTION_ARG_INT, &logger_port, "ZMQ logger port", NULL},
  {NULL}
};

static zlog_category_t *zc;
static void *logger = NULL;
static GMainLoop *loop;

static gchar *working_dir;
static gchar *daemon_exec;
static GPid daemon_pid = 0;
static guint daemon_log_stdout, daemon_log_stderr;

static GKeyFile *config_key_file = NULL;
static guint16 server_port = GPSD_DEFAULT_PORT;
static gchar *log_db_file;
static gchar *zmq_pub_addr;

#ifdef __GNUC__
#define GNUC_PACKED __attribute__((packed))
#else
#define GNUC_PACKED
#endif

#define GPSD_CLIENT_ALIVE_TIMEOUT 180

#define INHERITED_GPS_HDR \
  guint8 magic[2]; \
  guint8 msg_id; \
  guint16 length; \
  guint32 psn;

typedef struct
{
  INHERITED_GPS_HDR
  guint8 data[0];
} GNUC_PACKED gps_hdr_t;

typedef struct
{
  guint8 magic[2];
  guint8 msg_id;
  guint16 length;
  guint8 data[0];
} GNUC_PACKED gps_ack_hdr_t;

typedef struct
{
  INHERITED_GPS_HDR
  guint8 sub_code;
} GNUC_PACKED gps_logon_t;

typedef struct
{
  INHERITED_GPS_HDR
  guint8 data[1];
} GNUC_PACKED gps_report_t;

#define GPS_DATA_FLAG_VALID 0x80

typedef struct
{
  guint8 year;
  guint8 month;
  guint8 day;
  guint8 hour;
  guint8 minute;
  guint8 second;
  guint32 latitude;
  guint32 longitude;
  guint16 speed;
  guint16 azimuth;
  guint8 flag; // GPS_DATA_FLAG_xxx
} GNUC_PACKED gps_data_t;

typedef struct
{
  struct pt pt;
  guint8 data[1500];
  guint16 count;
} gps_rx_decode_t;

typedef struct
{
  zlog_category_t *zc;

  // TCP
  GSocketConnection *connection;

  // UDP
  GSocketAddress *udp_address;

  GSocket *socket; // TCP or UDP
  
  gps_rx_decode_t rx_decode;
  guint32 psn;
  guint32 packet_count;
  guint32 alive_timeout;
} gps_client_t;

struct gps_cmd_entry_tag;

typedef void (*gps_handler_t)(gps_client_t *client, guint8 *request, guint16 length);

typedef struct gps_cmd_entry_tag
{
  guint16 msg;
  gps_handler_t handler;
} gps_cmd_entry_t;

static guint16 gps_ack_sn = 0;

static GList *gps_client_list = NULL;
static GHashTable *gps_udp_client_list = NULL;

static gps_client_t *gps_udp_listener;

static void *gps_zsocket_pub;
static sqlite3 *gps_log_db;

#define MSG_HEAD1 0x29
#define MSG_HEAD2 0x29
#define MSG_END   0x0D

#define MSG_LOGON                    0xB1
#define MSG_GPS                      0x80
#define MSG_GENERAL_ACK              0x21

static void gps_general_ack(gps_client_t *client, guint8 *request, guint16 length);
static void gps_report(gps_client_t *client, guint8 *request, guint16 length);

// 处理函数列表
static const gps_cmd_entry_t gps_cmd_entries[] =
{
  {MSG_LOGON, gps_general_ack},
  {MSG_GPS, gps_report},
  {0xFF, NULL}
};

static gboolean gpsd_tcp_rx(GSocket *socket, GIOCondition cond, gpointer data);
static gboolean gpsd_udp_rx(GSocket *socket, GIOCondition cond, gpointer data);

//==============================================================================

/* select psn, datetime(time, 'unixepoch', 'localtime'), longitude, latitude from history; */
static void
gps_open_log_db(const gchar *file_name)
{
  g_assert(sqlite3_open(file_name, &gps_log_db) == SQLITE_OK);

  sqlite3_exec(gps_log_db,
    "CREATE TABLE [history] ("
    "  [psn] INTEGER NOT NULL, "
    "  [time] DATETIME NOT NULL, "
    "  [longitude] INTEGER NOT NULL DEFAULT 0, "
    "  [latitude] INTEGER NOT NULL DEFAULT 0, "    
    "  [altitude] INTEGER NOT NULL DEFAULT 0, "
    "  [speed] INTEGER NOT NULL DEFAULT 0, "
    "  [azimuth] INTEGER NOT NULL DEFAULT 0, "
    "  CONSTRAINT [] PRIMARY KEY ([psn], [time]));",
    NULL, NULL, NULL);

  sqlite3_exec(gps_log_db,
    "CREATE TABLE [last] ("
    "  [psn] INTEGER NOT NULL, "
    "  [time] DATETIME NOT NULL, "
    "  [longitude] INTEGER NOT NULL DEFAULT 0, "
    "  [latitude] INTEGER NOT NULL DEFAULT 0, "
    "  [altitude] INTEGER NOT NULL DEFAULT 0, "
    "  [speed] INTEGER NOT NULL DEFAULT 0, "
    "  [azimuth] INTEGER NOT NULL DEFAULT 0, "
    "  CONSTRAINT [] PRIMARY KEY ([psn]));",
    NULL, NULL, NULL);
}

static void
gps_close_log_db(void)
{
  if ( gps_log_db )
  {
    sqlite3_close(gps_log_db);
    gps_log_db = NULL;
  }
}

static void
gps_insert_to_log_db(gps_client_t *client, 
  gint longitude, gint latitude, gint altitude, gint speed, gint azimuth)
{
  int ret;
  sqlite3_stmt *stmt;
  GDateTime *now;
  gchar *msg;
  gboolean update_ok;
  zmsg_t *zmsg;
  
  now = g_date_time_new_now_local();

  sqlite3_prepare_v2(gps_log_db, "insert into history("
    "psn, time, longitude, latitude, altitude, speed, azimuth)"
    "values(?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, client->psn);
  sqlite3_bind_int64(stmt, 2, g_date_time_to_unix(now));
  sqlite3_bind_int(stmt, 3, longitude);
  sqlite3_bind_int(stmt, 4, latitude);
  sqlite3_bind_int(stmt, 5, altitude);
  sqlite3_bind_int(stmt, 6, speed);
  sqlite3_bind_int(stmt, 7, azimuth);
  ret = sqlite3_step(stmt);
  if (ret != SQLITE_DONE)
  {
    zlog_error(zc, "insert into history error: %d\n", ret);
  }
  sqlite3_finalize(stmt);

  // 更新 last 表
  sqlite3_prepare_v2(gps_log_db, "update last set "
    "time = ?, longitude = ?, latitude = ?, "
    "altitude = ?, speed = ?, azimuth = ? "
    "where (psn = ?)", -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, g_date_time_to_unix(now));
  sqlite3_bind_int(stmt, 2, longitude);
  sqlite3_bind_int(stmt, 3, latitude);
  sqlite3_bind_int(stmt, 4, altitude);
  sqlite3_bind_int(stmt, 5, speed);
  sqlite3_bind_int(stmt, 6, azimuth);
  sqlite3_bind_int(stmt, 7, client->psn);
  sqlite3_step(stmt);
  update_ok = sqlite3_changes(gps_log_db) > 0;
  sqlite3_finalize(stmt);

  if (!update_ok)
  {
    sqlite3_prepare_v2(gps_log_db, "insert into last("
      "psn, time, longitude, latitude, altitude, speed, azimuth)"
      "values(?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, client->psn);
    sqlite3_bind_int64(stmt, 2, g_date_time_to_unix(now));
    sqlite3_bind_int(stmt, 3, longitude);
    sqlite3_bind_int(stmt, 4, latitude);
    sqlite3_bind_int(stmt, 5, altitude);
    sqlite3_bind_int(stmt, 6, speed);
    sqlite3_bind_int(stmt, 7, azimuth);
    ret = sqlite3_step(stmt);
    if (ret != SQLITE_DONE)
    {
      zlog_error(zc, "insert into last error: %d\n", ret);
    }
    sqlite3_finalize(stmt);
  }

  msg = g_strdup_printf("{\
    \"type\": \"gps\", \
    \"time\": \"%d-%02d-%02d %02d:%02d:%02d\", \
    \"psn\": %d, \
    \"longitude\": %d, \
    \"latitude\": %d, \
    \"altitude\": %d, \
    \"speed\": %d, \
    \"azimuth\": %d}",
    g_date_time_get_year(now), g_date_time_get_month(now), g_date_time_get_day_of_month(now),
    g_date_time_get_hour(now), g_date_time_get_minute(now), g_date_time_get_second(now),
    client->psn, longitude, latitude, altitude, speed, azimuth);
  zmsg = zmsg_new();
  zmsg_addstr(zmsg, msg);
  zmsg_send(&zmsg, gps_zsocket_pub);
  g_free(msg);
  
  g_date_time_unref(now);
}

//==============================================================================


static void
gpsd_load_settings(void)
{
  int i;
  gchar *input_buf, *output_buf;
  gsize length;

  if (!g_file_test(GPSD_CONFIG_FILE, G_FILE_TEST_EXISTS))
  {
    zlog_error(zc, "Error: Config file does not exist!\n");
    goto out;
  }
  // 将文件的内容存入input_buf的字符串中
  if (!g_file_get_contents(GPSD_CONFIG_FILE, &input_buf, &length, NULL))
  {
    goto out;
  }
  // 将 input_buf 的字符串的编码由 GB2312 转换成 UTF-8 并存入 output_buf
  output_buf = g_convert(input_buf, -1, "UTF-8", "GB2312", NULL, NULL, NULL);
  g_free(input_buf);
  if (NULL == output_buf)
  {
    goto out;
  }
  config_key_file = g_key_file_new();
  g_key_file_load_from_data(config_key_file, output_buf, -1, G_KEY_FILE_NONE, NULL);
  g_free(output_buf);

  server_port = g_key_file_get_integer(config_key_file, "settings", "port", NULL);
  if (0 == server_port)
  {
    server_port = GPSD_DEFAULT_PORT;
  }
  zlog_notice(zc, "port: %d\n", server_port);

  log_db_file = g_key_file_get_string(config_key_file, "settings", "log_db", NULL);
  g_assert(log_db_file && *log_db_file);
  zlog_notice(zc, "log_db: %s\n", log_db_file);
  
  zmq_pub_addr = g_key_file_get_string(config_key_file, "settings", "zmq_pub", NULL);
  g_assert(zmq_pub_addr && *zmq_pub_addr);
  zlog_notice(zc, "zmq_pub: %s\n", zmq_pub_addr);
  
  return;
out:
  if ( config_key_file )
  {
    g_key_file_free(config_key_file);
  }
  config_key_file = NULL;
}

//==============================================================================

static void
gps_rx_decode_reset(gps_client_t *client)
{
  gps_rx_decode_t *decode = &client->rx_decode;

  PT_INIT(&decode->pt);
  decode->count = 0;
}

static guint8 
gps_calc_checksum(guint8 *data, guint32 len)
{
  int i;
  guint8 sum = 0;
  
  for(i = 0; i < len; ++i)
  {
    sum ^= data[i];
  }	
  return sum;
}

static char
gps_rx_decode_run(gps_client_t *client, guint8 c,
                     guint8 **packet, guint16 *length)
{
  int i;
  gps_rx_decode_t *decode = &client->rx_decode;
  struct pt *pt = &decode->pt;
  gps_hdr_t *hdr;
  guint8 ch;

  const gps_cmd_entry_t *entry;

  hdr = (gps_hdr_t *)decode->data;
  *packet = NULL;

  PT_BEGIN(pt);

  decode->count = 0;

  PT_WAIT_UNTIL(pt, c == MSG_HEAD1);
  decode->data[decode->count++] = c;
  PT_YIELD(pt);
  if (c != MSG_HEAD2)
  {
    PT_EXIT(pt);
  }
  decode->data[decode->count++] = c;

  while(decode->count < sizeof(gps_hdr_t))
  {
    PT_YIELD(pt);
    decode->data[decode->count++] = c;
  }

  hdr->length = g_ntohs(hdr->length);
  hdr->psn = g_ntohl(hdr->psn);

  // 长度字段包括 PSN
  while(decode->count < (sizeof(gps_hdr_t) + hdr->length - 4))
  {
    PT_YIELD(pt);
    decode->data[decode->count++] = c;
  }

  if (decode->data[decode->count - 1] != MSG_END)
  {
    zlog_error(client->zc, "packet end error!\n");
    PT_EXIT(pt);
  }
  if (gps_calc_checksum(decode->data, decode->count - 2) != decode->data[decode->count - 2])
  {
    zlog_error(client->zc, "packet chksum error!\n");
    PT_EXIT(pt);
  }

  *packet = decode->data;
  *length = decode->count;

  PT_END(pt);
}

static gps_client_t*
gps_client_new(GSocketConnection *connection)
{
  gps_client_t *client;
  GSource *source;
  gchar *s;
  gint fd;

  client = g_new0(gps_client_t, 1);
  g_assert(client);

  s = g_strdup_printf("%p", client);
  client->zc = zlog_get_category(s);
  g_free(s);
  g_assert(client->zc != NULL);

  client->connection = connection;
  g_object_ref(connection);
  gps_rx_decode_reset(client);

  client->udp_address = NULL;
  
  client->socket = g_socket_connection_get_socket(connection);

  source = g_socket_create_source(client->socket, G_IO_IN, NULL);
  g_source_set_callback(source, (GSourceFunc)gpsd_tcp_rx, client, NULL);
  g_source_attach(source, NULL);
  g_source_unref(source);

  client->psn = 0;

  client->alive_timeout = GPSD_CLIENT_ALIVE_TIMEOUT;

  gps_client_list = g_list_append(gps_client_list, client);
  
  return client;
}

static gps_client_t*
gps_udp_client_new(GSocket *socket, guint32 psn)
{
  gps_client_t *client;
  gchar s[256];

  client = g_new0(gps_client_t, 1);
  g_assert(client);

  client->connection = NULL;

  client->udp_address = NULL;
  
  client->socket = socket;
  gps_rx_decode_reset(client);

  client->psn = psn;
  if ( psn )
  {
    snprintf(s, sizeof(s), "UDP_%d", client->psn);
  }
  else
  {
    snprintf(s, sizeof(s), "UDP_listener");
  }
  client->zc = zlog_get_category(s);

  client->alive_timeout = GPSD_CLIENT_ALIVE_TIMEOUT;

  g_hash_table_insert(gps_udp_client_list, GINT_TO_POINTER(client->psn), client);

  return client;
}

static void
gps_client_free(gps_client_t *client)
{
  zlog_notice(client->zc, "closed !!!\n");

  gps_client_list = g_list_remove(gps_client_list, client);

  if (client->connection)
  {
    g_object_unref(client->connection);
    client->connection = NULL;
  }
  if (client->udp_address)
  {
    g_object_unref(client->udp_address);
    client->udp_address = NULL;
  }
  g_free(client);
}

void
gps_client_replace_udp_address(gps_client_t* client, GSocketAddress *address)
{
  if (client->udp_address)
  {
    g_object_unref(client->udp_address);
  }
  client->udp_address = address;
}

static void
gps_send(gps_client_t *client, guint8 msg, void *data, guint16 length)
{
  int i;
  gchar psn[12];
  GError *error = NULL;
  guint8 tx_buf[4096];
  gps_ack_hdr_t *hdr = (gps_ack_hdr_t *)tx_buf;
  guint8 *encoded_buf = tx_buf;
  guint8 chksum;
  gsize to_send;

  if (length > 1024)
  {
    zlog_error(zc, "xxxxxxxxxxxxxxx gps_send data too large: %d !!!\n", length);
    return;
  }

  hdr->magic[0] = MSG_HEAD1;
  hdr->magic[1] = MSG_HEAD2;
  hdr->msg_id = msg;
  hdr->length = g_htons(length + 2);
  memcpy(hdr->data, data, length);
  hdr->data[length] = gps_calc_checksum(tx_buf, sizeof(gps_ack_hdr_t) + length);
  hdr->data[length + 1] = MSG_END;

  to_send = sizeof(gps_ack_hdr_t) + length + 2;
  
  zlog_info(client->zc, "<==== msg: 0x%02X count: %d\n", msg, to_send);
  hzlog_debug(client->zc, tx_buf, to_send > 256 ? 256 : to_send);

  if (client->udp_address)
  {
    g_socket_send_to(client->socket, client->udp_address, tx_buf, to_send, NULL, &error);
  }
  else
  {
    g_socket_send(client->socket, tx_buf, to_send, NULL, &error);
  }
  g_clear_error(&error);
}

static void
gps_general_ack(gps_client_t *client, guint8 *request, guint16 length)
{
  gps_hdr_t *hdr = (gps_hdr_t *)request;
  guint8 ack[3];

  ack[0] = request[length - 2]; // checksum
  ack[1] = hdr->msg_id;
  ack[2] = hdr->data[0];
  
  //zlog_notice(client->zc, "gps_logon: %s\n", client->psn);
  gps_send(client, MSG_GENERAL_ACK, ack, sizeof(ack));
}

static gint32
gps_bcd2hex(guint32 v)
{
  gint32 retval;
  gchar s[64];

  snprintf(s, sizeof(s), "%x", v & 0x7FFFFFFF);
  retval = atol(s);
  if (v & 0x80000000)
  {
    retval *= -1;
  }
  return retval;
}

static void
gps_report(gps_client_t *client, guint8 *request, guint16 length)
{
  gps_data_t *data = (gps_data_t *)((gps_report_t*)request)->data;

  if (data->flag & GPS_DATA_FLAG_VALID)
  {
    data->latitude = gps_bcd2hex(g_ntohl(data->latitude));
    data->longitude = gps_bcd2hex(g_ntohl(data->longitude));
    data->speed = gps_bcd2hex(g_ntohs(data->speed));
    data->azimuth = gps_bcd2hex(g_ntohs(data->azimuth)) % 360;
  }
  else
  {
    data->latitude = 0;
    data->longitude = 0;
    data->speed = 0;
    data->azimuth = 0;
  }
  gps_insert_to_log_db(client, data->longitude, data->latitude, 0, data->speed, data->azimuth);
  gps_general_ack(client, request, length);
}

gboolean
gpsd_new_connection(GSocketService *service,
  GSocketConnection *connection, GObject *source_object, gpointer user_data)
{
  gps_client_t *client;
  GSocketAddress *sockaddr = g_socket_connection_get_remote_address(connection, NULL);
  GInetAddress *addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(sockaddr));
  guint16 port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(sockaddr));
  gchar *ip = g_inet_address_to_string(addr);

  zlog_notice(zc, "New Connection from %s:%d\n", ip, port);
  
  client = gps_client_new(connection);

  g_free(ip);
  g_object_unref(sockaddr);

  return TRUE;
}

static gboolean
gpsd_tcp_rx(GSocket *socket, GIOCondition cond, gpointer user_data)
{
  int i;
  gps_client_t *client = user_data;
  GError *error = NULL;
  guint8 buf[4096];
  gssize bytes_read;
  GIOStatus ret;
  guint8 *packet;
  guint16 count;
  gps_hdr_t *hdr;
  gchar s[256];
  const gps_cmd_entry_t *entry;

  if (cond & G_IO_HUP)
  {
    gps_client_free(client);
    return G_SOURCE_REMOVE;
  }

  bytes_read = g_socket_receive(socket, buf, sizeof(buf), NULL, &error);

  if (error || bytes_read <= 0)
  {
    if (error)
    {
      zlog_error(client->zc, "Error reading: %s\n", error->message);
      g_clear_error(&error);
    }
    gps_client_free(client);
    return G_SOURCE_REMOVE;
  }

  //zlog_debug(client->zc, "====> %d\n", bytes_read);
  //hzlog_debug(client->zc, buf, bytes_read);
  
  for(i = 0; i < bytes_read; ++i)
  {
    gps_rx_decode_run(client, buf[i], &packet, &count);
    if ( packet )
    {
      client->alive_timeout = GPSD_CLIENT_ALIVE_TIMEOUT;
      
      hdr = (gps_hdr_t *)packet;

      if (client->psn == 0)
      {
        client->psn = hdr->psn;
        snprintf(s, sizeof(s), "TCP_%d", client->psn);
        client->zc = zlog_get_category(s);        
      }
  
      zlog_info(client->zc, "====> msg: 0x%02X count: %d\n", hdr->msg_id, count);
      hzlog_debug(client->zc, packet, count > 64 ? 64 : count);
  
      for(entry = gps_cmd_entries; entry->msg != 0xFF; ++entry)
      {
        if (entry->msg == hdr->msg_id)
        {
          entry->handler(client, packet, count);
          break;
        }
      }
    }
  }
  return G_SOURCE_CONTINUE;
}

static gboolean
gpsd_udp_rx(GSocket *socket, GIOCondition cond, gpointer user_data)
{
  int i;
  gps_client_t *listener = user_data;
  gps_client_t *client = NULL;
  GSocketAddress *address = NULL;
  GError *error = NULL;
  guint8 buf[1500];
  gssize bytes_read;
  guint8 *packet;
  guint16 count;
  gps_hdr_t *hdr;
  gchar s[256], psn[16];
  const gps_cmd_entry_t *entry;
  
  bytes_read = g_socket_receive_from(socket, &address, buf, sizeof(buf), NULL, &error);
  
  if (error || bytes_read <= 0)
  {
    if (error)
    {
      zlog_error(listener->zc, "Error reading: %s\n", error->message);
      g_clear_error(&error);
    }
    else
    {
      zlog_notice(listener->zc, "closed !!!\n");
    }
    return G_SOURCE_REMOVE;
  }

  for(i = 0; i < bytes_read; ++i)
  {
    gps_rx_decode_run(listener, buf[i], &packet, &count);
    if ( packet )
    {
      listener->alive_timeout = GPSD_CLIENT_ALIVE_TIMEOUT;
      
      hdr = (gps_hdr_t *)packet;

      client = g_hash_table_lookup(gps_udp_client_list, GINT_TO_POINTER(hdr->psn));
      if (NULL == client)
      {
        client = gps_udp_client_new(socket, hdr->psn);
        g_assert(NULL != client);
        gps_client_list = g_list_append(gps_client_list, client);
      }
      // 更新地址信息
      gps_client_replace_udp_address(client, address);
      client->alive_timeout = GPSD_CLIENT_ALIVE_TIMEOUT;
  
      zlog_info(client->zc, "====> msg: 0x%02X count: %d\n", hdr->msg_id, count);
      hzlog_debug(client->zc, packet, count > 64 ? 64 : count);
  
      for(entry = gps_cmd_entries; entry->msg != MSG_END; ++entry)
      {
        if (entry->msg == hdr->msg_id)
        {
          entry->handler(client, packet, count);
          break;
        }
      }
    }
  }
  if (NULL == client)
  {
    g_object_unref(address);
  }
  return G_SOURCE_CONTINUE;
}

static void
sig_handler(int signum)
{
  zlog_warn(zc, "sig received: %d\n", signum);
  kill(daemon_pid, signum);
  g_main_loop_quit(loop);
}

static gboolean
daemon_log_callback(GIOChannel *source,
                    GIOCondition condition, gpointer data)
{
  gchar line[4096];
  gsize bytes_read;
  GIOStatus status;

  if (condition & G_IO_IN)
  {
    if ((status = g_io_channel_read_chars(source, line, sizeof(line) - 1, &bytes_read, NULL)) == G_IO_STATUS_NORMAL)
    {
      if ( bytes_read )
      {
        line[bytes_read] = 0;
        //zlog_info(zc, line);
      }
    }
    return G_SOURCE_CONTINUE;
  }
  else
  {
    return G_SOURCE_REMOVE;
  }
}

static gboolean
daemon_start(void)
{
  GError *error = NULL;
  gint argc = 0;
  gchar *argv[8];
  gchar ss[64];
  gint out_fd, err_fd;
  GIOChannel *ch;

  argv[argc++] = daemon_exec;
  if ( logger_port )
  {
    argv[argc++] = "-l";
    snprintf(ss, sizeof(ss), "%d", logger_port);
    argv[argc++] = ss;
  }
  argv[argc] = NULL;

  if (!g_spawn_async_with_pipes(working_dir, argv, NULL,
                                G_SPAWN_SEARCH_PATH,// 不使用 G_SPAWN_DO_NOT_REAP_CHILD 避免出现僵尸进程
                                NULL, NULL,
                                &daemon_pid,
                                NULL, &out_fd, &err_fd,
                                &error))
  {
    g_strfreev(argv);
    zlog_error(zc, "daemon start failed: %s\n", error->message);
    g_clear_error(&error);
    return FALSE;
  }

  if (ch = g_io_channel_unix_new(out_fd))
  {
    g_io_channel_set_encoding(ch, NULL, NULL);
    g_io_channel_set_buffered(ch, FALSE); // 设置后如有中文会卡死
    g_io_channel_set_close_on_unref(ch, TRUE);
    daemon_log_stdout = g_io_add_watch(ch, G_IO_IN | G_IO_HUP,
                                       daemon_log_callback, NULL);
    g_io_channel_unref(ch);
  }

  if (ch = g_io_channel_unix_new(err_fd))
  {
    g_io_channel_set_encoding(ch, NULL, NULL);
    g_io_channel_set_buffered(ch, FALSE); // 设置后如有中文会卡死
    g_io_channel_set_close_on_unref(ch, TRUE);
    daemon_log_stderr = g_io_add_watch(ch, G_IO_IN | G_IO_HUP,
                                       daemon_log_callback, NULL);
    g_io_channel_unref(ch);
  }
  return TRUE;
}

static gboolean
daemon_check_exit()
{
  if ((daemon_pid > 0) && (kill(daemon_pid, 0) < 0))
  {
    zlog_warn(zc, "daemon service exit!\n");
    g_source_remove(daemon_log_stdout);
    g_source_remove(daemon_log_stderr);
    daemon_pid = -1;
    if ( daemon_start() )
    {
      zlog_info(zc, "daemon start ok\n");
    }
  }
  return G_SOURCE_CONTINUE;
}

static int
log_output(zlog_msg_t *msg)
{
  zmsg_t *zmsg;

  if ( logger )
  {
    zmsg = zmsg_new();
    zmsg_addmem(zmsg, msg->path, strlen(msg->path) + 1);
    zmsg_addmem(zmsg, msg->buf, msg->len);
    zmsg_send(&zmsg, logger);
  }
  else
  {
    write(STDOUT_FILENO, msg->buf, msg->len);
  }
  return 0;
}

static gboolean
gpsd_poll(gpointer user_data)
{
  GList *list;
  GList *to_remove = NULL;
  gps_client_t *client;

  //zlog_info(zc, "alive client count: %d\n", g_list_length(gps_client_list));
  
  for(list = g_list_first(gps_client_list); list != NULL; list = g_list_next(list))
  {
    client = list->data;
    if (client->alive_timeout > 0)
    {
      client->alive_timeout--;
    }
    if (0 == client->alive_timeout)
    {
      to_remove = g_list_append(to_remove, client);
    }
  }
  for(list = g_list_first(to_remove); list != NULL; list = g_list_next(list))
  {
    client = list->data;
    zlog_notice(client->zc, "closed for timeout !!!\n");
    gps_client_free(client);
  }
  if (to_remove)
  {
    g_list_free(to_remove);
  }
  return G_SOURCE_CONTINUE;
}

int main(int argc, char **argv)
{
  int retval = -1;
  GError *error = NULL;
  GOptionContext *context;
  zctx_t *zctx;
  GSocketService *service;
  GInetAddress *address;
  GSocketAddress *socket_address;
  GSocket *udp_socket;
  GSource *source;
  
  working_dir = g_get_current_dir();
  daemon_exec = argv[0];

  context = g_option_context_new("- GPS Test Service");
  g_option_context_add_main_entries(context, cmd_entries, NULL);
  if ( !g_option_context_parse(context, &argc, &argv, &error) )
  {
    g_clear_error(&error);
    return -1;
  }
  g_clear_error(&error);

  zctx = zctx_shadow_zmq_ctx(zmq_ctx_new());
  
  if ( logger_port )
  {
    logger = zsocket_new(zctx, ZMQ_PUB);
    g_assert(logger != NULL);
    zsocket_bind(logger, "tcp://*:%d", logger_port);
  }

  if (zlog_init("/etc/gpsd/zlog.conf") != 0)
  {
    zlog_init(NULL);
  }
  zlog_set_record("logger", log_output);

  if ( kill_daemon )
  {
    return UtilsDaemonKill(argv[0]);
  }
  if ( run_as_daemon )
  {
    retval = UtilsDaemonStart(argv[0]);

    if (0 != retval)
    {
      goto out;
    }
    //umask(0);
  }
  zc = zlog_get_category(run_as_daemon ? "server_syslog" : "server");
  g_assert(zc != NULL);

  g_type_init();

  if ( run_as_daemon )
  {
    if (!daemon_start())
    {
      goto out;
    }
    UtilsSigSetup(SIGINT, sig_handler);
    UtilsSigSetup(SIGTERM, sig_handler);
    UtilsSigSetup(SIGHUP, sig_handler);

    g_timeout_add_seconds(1, daemon_check_exit, NULL);
  }
  else
  {
    gpsd_load_settings();

    gps_open_log_db(log_db_file);
    
    gps_zsocket_pub = zsocket_new(zctx, ZMQ_PUB);
    g_assert(zsocket_bind(gps_zsocket_pub, zmq_pub_addr) != -1);

    // TCP
    service = g_socket_service_new();
    address = g_inet_address_new_any(G_SOCKET_FAMILY_IPV4);
    socket_address = g_inet_socket_address_new(address, server_port);

    g_socket_listener_add_address(G_SOCKET_LISTENER(service), socket_address, G_SOCKET_TYPE_STREAM,
                                  G_SOCKET_PROTOCOL_TCP, NULL, NULL, NULL);

    g_object_unref(socket_address);
    g_object_unref(address);
    g_socket_service_start(service);

    g_signal_connect(service, "incoming", G_CALLBACK(gpsd_new_connection), NULL);

    // UDP
    udp_socket = g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM, 0, NULL);
    g_assert(udp_socket);
    socket_address = g_inet_socket_address_new(g_inet_address_new_any(G_SOCKET_FAMILY_IPV4), server_port);
    if (!g_socket_bind(udp_socket, socket_address, FALSE, &error))
    {
      zlog_error(zc, "g_socket_bind: %s\n", error->message);
      g_assert_not_reached();
    }
    g_object_unref(socket_address);
  
    gps_udp_client_list = g_hash_table_new(g_direct_hash, g_direct_equal);
    
    gps_udp_listener = gps_udp_client_new(udp_socket, 0);

    source = g_socket_create_source(udp_socket, G_IO_IN, NULL);
    g_source_set_callback(source, (GSourceFunc)gpsd_udp_rx, gps_udp_listener, NULL);
    g_source_attach(source, NULL);
    g_source_unref(source);
  
    g_socket_set_blocking(udp_socket, FALSE);

    g_timeout_add_seconds(1, gpsd_poll, NULL);
  }
  loop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(loop);

  if ( !run_as_daemon )
  {
    zsocket_destroy(zctx, gps_zsocket_pub);
    
    gps_close_log_db();

    zsocket_destroy(zctx, logger);
    zctx_destroy(&zctx);
  }
  g_main_loop_unref(loop);

  retval = 0;
out:
  zlog_fini();
  if ( run_as_daemon )
  {
    UtilsDaemonStop();
  }
  return retval;
}

