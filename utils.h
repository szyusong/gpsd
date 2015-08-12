#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>
#include <glib.h>
#include <gio/gio.h>
#include <gio/gunixsocketaddress.h>
#include <zlog.h>

#define DISABLE_DOMAIN_LOG() DummyDomainLog(G_LOG_DOMAIN)

typedef void(*utils_popen_for_each_cb_t)(const gchar *item, void *param);

uint8_t bcd2bin(uint8_t n);
uint8_t bin2bcd(uint8_t n);
uint8_t chk_xrl(uint8_t *buffer, uint16_t length);
guint8* hdlc_encode_buf(guint8 *buf, guint8 c);

size_t strlcpy(char *dest, const char *src, size_t len);
unsigned long simple_strtoul(const char *cp,char **endp,unsigned int base);
long simple_strtol(const char *cp,char **endp,unsigned int base);

void ttySetDTR(int tty_fd, int on);
gboolean ttySetup(int tty_fd, gboolean local, gboolean crtscts, int baudrate);

void UtilsSigSetup(int signum, void (*sig_handler)(int signum));
void UtilsSigRestore(int signum);

void UtilsDummyDomainLog(const gchar *log_domain);
GString* UtilsDumpBin(const void *data, guint length);

guint32 UtilsGetMs(void);
void UtilsDelayMs(guint ms);

void UtilsCanonicalizeFileName(gchar *filename);
gchar* UtilsResolveSymlink(const gchar *file);

gchar* UtilsStripCRLF(gchar *s, gint length);

gint UtilsExec(zlog_category_t *zc, const gchar *fmt, ...);
gchar* UtilsPopen(const gchar *command);
void UtilsPopenForEach(const gchar *command, utils_popen_for_each_cb_t cb, void *param);
gchar* UtilsReadFileAsString(const gchar *path, const gchar *file);
guint UtilsReadFileAsInt(const gchar *path, const gchar *file, guint default_value);
guint UtilsReadFileAsHex(const gchar *path, const gchar *file, guint default_value);
ssize_t UtilsSafeRead(int fd, void *buf, size_t count);
ssize_t UtilsFullRead(int fd, void *buf, size_t len);
ssize_t UtilsSafeWrite(int fd, const void *buf, size_t count);
ssize_t UtilsFullWrite(int fd, const void *buf, size_t len);
gboolean UtilsWriteAll(gint fd, gconstpointer vbuf, gsize to_write);

gchar* UtilsCheckMount(const gchar *device_name);

gint UtilsDaemonKill(gchar *ident);
gint UtilsDaemonStart(gchar *ident);
void UtilsDaemonStop(void);
void UtilsDaemonLog(int prio, const char* template, ...);

gboolean UtilsMakeConnection (const char *hostname, guint16 port,
                              GCancellable     *cancellable,
                              guint             timeout,
                              gboolean          use_udp,
                              GSocket         **socket,
                              GSocketAddress  **address,
                              GError          **error);

gint UtilsNetworkCheck(const gchar *server);

gboolean UtilsCreateThread(pthread_t *thread, int priority,
  void *(*routine)(void *), void *arg);

void UtilsPostWork(void (*work)(void *param), void *param);

gboolean UtilsGetMac(const gchar *name, guint8 *mac);

gboolean UtilsH264IsKeyFrame(guint8 *data);

void UtilsBacktrace(zlog_category_t *zc);

#endif /* _UTILS_H_ */
