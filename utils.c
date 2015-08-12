
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <mntent.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>
#include <sys/unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <execinfo.h>

#include <libdaemon/daemon.h>

#include "utils.h"

typedef void (*sighandler_t)(int);

#ifdef BCD_USE_TABLE
const uint8_t bcd2bin_data[] =
{
  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 0, 0, 0, 0, 0, 0,
  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 0, 0, 0, 0, 0, 0,
  20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 0, 0, 0, 0, 0, 0,
  30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 0, 0, 0, 0, 0, 0,
  40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 0, 0, 0, 0, 0, 0,
  50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 0, 0, 0, 0, 0, 0,
  60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 0, 0, 0, 0, 0, 0,
  70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 0, 0, 0, 0, 0, 0,
  80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 0, 0, 0, 0, 0, 0,
  90, 91, 92, 93, 94, 95, 96, 97, 98, 99
};

const uint8_t bin2bcd_data[] =
{
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
  0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99
};
#endif

#ifdef G_OS_UNIX
static const char *unix_socket_address_types[] =
{
  "invalid",
  "anonymous",
  "path",
  "abstract",
  "padded"
};
#endif

uint8_t bcd2bin(uint8_t n)
{
#ifdef BCD_USE_TABLE
  return pgm_read_byte(bcd2bin_data + n);
#else
  uint8_t x = (n & 0xF0) >> 4;

  if (x > 9 || (n & 0x0F) > 9)
  {
    return 0;
  }
  else
  {
    return (x << 3) + (x << 1) + (n & 0x0F);
  }
#endif
}

uint8_t bin2bcd(uint8_t n)
{
#ifdef BCD_USE_TABLE
  return pgm_read_byte(bin2bcd_data + n);
#else
  uint8_t result = 0;

  if (n > 99)
  {
    return 0;
  }
  while(n > 9)
  {
    ++result;
    n -= 10;
  }
  return (result << 4) | n;
#endif
}

uint8_t
chk_xrl(uint8_t *buffer, uint16_t length)
{
  unsigned char tempxr;
  uint8_t  *bufferxr;
  uint16_t  lengthxr;

  bufferxr = buffer;
  lengthxr = length;

  tempxr = *bufferxr++;
  lengthxr--;
  while(lengthxr--)
  {
    tempxr = tempxr ^ (*bufferxr++);
  }
  return tempxr;
}

guint8*
hdlc_encode_buf(guint8 *buf, guint8 c)
{
  switch (c)
  {
  case 0x7D:
    *buf++ = 0x7D;
    *buf++ = 0x01;
    break;

  case 0x7E:
    *buf++ = 0x7D;
    *buf++ = 0x02;
    break;

  default:
    *buf++ = c;
    break;
  }
  return buf;
}

size_t
strlcpy(char *dest, const char *src, size_t len)
{
  size_t ret = strlen(src);

  if (len != 0)
  {
    if (ret < len)
    {
      strcpy(dest, src);
    }
    else
    {
      strncpy(dest, src, len - 1);
      dest[len - 1] = 0;
    }
  }
  return ret;
}

unsigned long simple_strtoul(const char *cp,char **endp,unsigned int base)
{
	unsigned long result = 0,value;

	if (*cp == '0') {
		cp++;
		if ((*cp == 'x') && isxdigit(cp[1])) {
			base = 16;
			cp++;
		}
		if (!base) {
			base = 8;
		}
	}
	if (!base) {
		base = 10;
	}
	while (isxdigit(*cp) && (value = isdigit(*cp) ? *cp-'0' : (islower(*cp)
	    ? toupper(*cp) : *cp)-'A'+10) < base) {
		result = result*base + value;
		cp++;
	}
	if (endp)
		*endp = (char *)cp;
	return result;
}

long simple_strtol(const char *cp,char **endp,unsigned int base)
{
	if(*cp=='-')
		return -simple_strtoul(cp+1,endp,base);
	return simple_strtoul(cp,endp,base);
}

//==============================================================================

static char *
socket_address_to_string (GSocketAddress *address)
{
  char *res = NULL;

  if (G_IS_INET_SOCKET_ADDRESS (address))
  {
    GInetAddress *inet_address;
    char *str;
    int port;

    inet_address = g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (address));
    str = g_inet_address_to_string (inet_address);
    port = g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (address));
    res = g_strdup_printf ("%s:%d", str, port);
    g_free (str);
  }
#ifdef G_OS_UNIX
  else if (G_IS_UNIX_SOCKET_ADDRESS (address))
  {
    GUnixSocketAddress *uaddr = G_UNIX_SOCKET_ADDRESS (address);

    res = g_strdup_printf ("%s:%s",
                           unix_socket_address_types[g_unix_socket_address_get_address_type (uaddr)],
                           g_unix_socket_address_get_path (uaddr));
  }
#endif

  return res;
}

static GSocketAddress *
socket_address_from_string (const char *name)
{
#ifdef G_OS_UNIX
  int i, len;

  for (i = 0; i < G_N_ELEMENTS (unix_socket_address_types); i++)
  {
    len = strlen (unix_socket_address_types[i]);
    if (!strncmp (name, unix_socket_address_types[i], len) &&
        name[len] == ':')
    {
      return g_unix_socket_address_new_with_type (name + len + 1, -1,
             (GUnixSocketAddressType)i);
    }
  }
#endif
  return NULL;
}

//==============================================================================

/* We can get an EIO error on an ioctl if the modem has hung up */
#define ok_error(num) ((num)==EIO)

/*
 * List of valid speeds.
 */

static struct speed
{
  int speed_int, speed_val;
} speeds[] =
{
#ifdef B50
  { 50, B50 },
#endif
#ifdef B75
  { 75, B75 },
#endif
#ifdef B110
  { 110, B110 },
#endif
#ifdef B134
  { 134, B134 },
#endif
#ifdef B150
  { 150, B150 },
#endif
#ifdef B200
  { 200, B200 },
#endif
#ifdef B300
  { 300, B300 },
#endif
#ifdef B600
  { 600, B600 },
#endif
#ifdef B1200
  { 1200, B1200 },
#endif
#ifdef B1800
  { 1800, B1800 },
#endif
#ifdef B2000
  { 2000, B2000 },
#endif
#ifdef B2400
  { 2400, B2400 },
#endif
#ifdef B3600
  { 3600, B3600 },
#endif
#ifdef B4800
  { 4800, B4800 },
#endif
#ifdef B7200
  { 7200, B7200 },
#endif
#ifdef B9600
  { 9600, B9600 },
#endif
#ifdef B19200
  { 19200, B19200 },
#endif
#ifdef B38400
  { 38400, B38400 },
#endif
#ifdef B57600
  { 57600, B57600 },
#endif
#ifdef B76800
  { 76800, B76800 },
#endif
#ifdef B115200
  { 115200, B115200 },
#endif
#ifdef EXTA
  { 19200, EXTA },
#endif
#ifdef EXTB
  { 38400, EXTB },
#endif
#ifdef B230400
  { 230400, B230400 },
#endif
#ifdef B460800
  { 460800, B460800 },
#endif
#ifdef B921600
  { 921600, B921600 },
#endif
#ifdef B1000000
  { 1000000, B1000000 },
#endif
#ifdef B1152000
  { 1152000, B1152000 },
#endif
#ifdef B1500000
  { 1500000, B1500000 },
#endif
#ifdef B2000000
  { 2000000, B2000000 },
#endif
#ifdef B2500000
  { 2500000, B2500000 },
#endif
#ifdef B3000000
  { 3000000, B3000000 },
#endif
#ifdef B3500000
  { 3500000, B3500000 },
#endif
#ifdef B4000000
  { 4000000, B4000000 },
#endif
  { 0, 0 }
};

/********************************************************************
 *
 * Translate from bits/second to a speed_t.
 */

static int translate_speed (int bps)
{
  struct speed *speedp;

  if (bps != 0)
  {
    for (speedp = speeds; speedp->speed_int; speedp++)
    {
      if (bps == speedp->speed_int)
      {
        return speedp->speed_val;
      }
    }
    warn("speed %d not supported", bps);
  }
  return 0;
}

/********************************************************************
 *
 * setdtr - control the DTR line on the serial port.
 * This is called from die(), so it shouldn't call die().
 */

void
ttySetDTR(int tty_fd, int on)
{
  int modembits = TIOCM_DTR;

  ioctl(tty_fd, (on ? TIOCMBIS : TIOCMBIC), &modembits);
}

/********************************************************************
 *
 * set_up_tty: Set up the serial port on `fd' for 8 bits, no parity,
 * at the requested speed, etc.  If `local' is true, set CLOCAL
 * regardless of whether the modem option was specified.
 */

gboolean
ttySetup(int tty_fd, gboolean local, gboolean crtscts, int baudrate)
{
  int speed;
  struct termios tios;

  ttySetDTR(tty_fd, 1);
  if (tcgetattr(tty_fd, &tios) < 0)
  {
    if (!ok_error(errno))
    {
      return FALSE;
    }
    return TRUE;
  }

  tios.c_cflag     &= ~(CSIZE | CSTOPB | PARENB | CLOCAL);
  tios.c_cflag     |= CS8 | CREAD | HUPCL;

  tios.c_iflag      = IGNBRK | IGNPAR;
  tios.c_oflag      = 0;
  tios.c_lflag      = 0;
  tios.c_cc[VMIN]   = 1;
  tios.c_cc[VTIME]  = 0;

  if ( local ) // 对于物理串口 CLOCAL 很关键, 不设置会导致只能打开一次
  {
    tios.c_cflag ^= (CLOCAL | HUPCL);
  }
  if ( crtscts ) // 硬件流控
  {
    tios.c_cflag |= CRTSCTS;
  }
  else
  {
    tios.c_cflag &= ~CRTSCTS;
  }
  speed = translate_speed(baudrate);
  cfsetospeed (&tios, speed);
  cfsetispeed (&tios, speed);

  while (tcsetattr(tty_fd, TCSAFLUSH, &tios) < 0 && !ok_error(errno))
  {
    if (errno != EINTR)
    {
      return FALSE;
    }
  }
  return TRUE;
}

//==============================================================================

void
UtilsSigSetup(int signum, void (*sig_handler)(int signum))
{
  struct sigaction action;

  memset(&action, 0, sizeof (action));
  action.sa_handler = sig_handler;

  sigaction(signum, &action, NULL);
}

void
UtilsSigRestore(int signum)
{
  struct sigaction action;

  memset(&action, 0, sizeof (action));
  action.sa_handler = SIG_DFL;

  sigaction(signum, &action, NULL);
}

static void
sig_restore(int signum)
{
  struct sigaction action;

  memset(&action, 0, sizeof (action));
  action.sa_handler = SIG_DFL;

  sigaction(signum, &action, NULL);
}

static void
utils_dummy_log(const gchar *log_domain, GLogLevelFlags log_level,
                const gchar *message, gpointer user_data)
{
}

void
UtilsDummyDomainLog(const gchar *log_domain)
{
  g_log_set_handler(log_domain, G_LOG_LEVEL_MASK, utils_dummy_log, NULL);
}

GString*
UtilsDumpBin(const void *data, guint length)
{
  const gchar *p;
  gchar c;
  guint k, nb, nl, offset;
  GString *s = g_string_new("");

  p = data;
  nb = length;
  offset = 0;
#ifdef CONFIG_DUMP_BIN_WITH_TITLE
  g_string_append(s, "----------------------------------------------------------+-----------------\n");
  g_string_append(s, " offset   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | \n");
  g_string_append(s, "----------------------------------------------------------+-----------------\n");
#endif
  do
  {
    nl = (nb < 16) ? nb : 16;
    g_string_append_printf(s, "%08X ", offset);
    for (k = 0; k < nl; ++k)
    {
      g_string_append_printf(s, " %.2X", p[k]);
    }
    for (; k < 16; ++k)
    {
      g_string_append_printf(s, "   ");
    }
#ifdef CONFIG_DUMP_BIN_WITH_TITLE
    g_string_append_printf(s, " | ");
#else
    g_string_append_printf(s, "   ");
#endif
    for (k = 0; k < nl; ++k)
    {
      c = p[k];
      g_string_append_printf(s, "%c", (' ' <= c && c <= '~') ? c : '.');
    }
    g_string_append_printf(s, "\n");
    p += nl;
    nb -= nl;
    offset += 16;
  }
  while (nb > 0);
  return s;
}

//==============================================================================

guint32 
UtilsGetMs(void)
{
  GTimeVal tv;

  g_get_current_time(&tv);
  return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void
UtilsDelayMs(guint ms)
{
  struct timeval delay;

  delay.tv_sec = 0;
  delay.tv_usec = ms * 1000;
  select(0, NULL, NULL, NULL, &delay);
}

/* borrowed from gtk/gtkfilesystemunix.c in GTK+ on 02/23/2006 */
void
UtilsCanonicalizeFileName(gchar *filename)
{
  gchar *p, *q;
  gboolean last_was_slash = FALSE;

  p = filename;
  q = filename;

  while (*p)
  {
    if (*p == G_DIR_SEPARATOR)
    {
      if (!last_was_slash)
      {
        *q++ = G_DIR_SEPARATOR;
      }

      last_was_slash = TRUE;
    }
    else
    {
      if (last_was_slash && *p == '.')
      {
        if (*(p + 1) == G_DIR_SEPARATOR ||
            *(p + 1) == '\0')
        {
          if (*(p + 1) == '\0')
          {
            break;
          }

          p += 1;
        }
        else if (*(p + 1) == '.' &&
                 (*(p + 2) == G_DIR_SEPARATOR ||
                  *(p + 2) == '\0'))
        {
          if (q > filename + 1)
          {
            q--;
            while (q > filename + 1 &&
                   *(q - 1) != G_DIR_SEPARATOR)
            {
              q--;
            }
          }

          if (*(p + 2) == '\0')
          {
            break;
          }

          p += 2;
        }
        else
        {
          *q++ = *p;
          last_was_slash = FALSE;
        }
      }
      else
      {
        *q++ = *p;
        last_was_slash = FALSE;
      }
    }

    p++;
  }

  if (q > filename + 1 && *(q - 1) == G_DIR_SEPARATOR)
  {
    q--;
  }

  *q = '\0';
}

/*
 * 参考 gunixmounts.c 中的 _resolve_symlink
 */
gchar*
UtilsResolveSymlink(const gchar *file)
{
  GError *error;
  gchar *dir;
  gchar *link;
  gchar *f;
  gchar *f1;

  f = g_strdup (file);

  while (g_file_test (f, G_FILE_TEST_IS_SYMLINK))
  {
    link = g_file_read_link(f, &error);
    if (link == NULL)
    {
      g_error_free (error);
      g_free (f);
      f = NULL;
      goto out;
    }

    dir = g_path_get_dirname(f);
    f1 = g_strdup_printf ("%s/%s", dir, link);
    g_free(dir);
    g_free(link);
    g_free(f);
    f = f1;
  }

out:
  if (f != NULL)
  {
    UtilsCanonicalizeFileName (f);
  }
  return f;
}

gchar*
UtilsStripCRLF(gchar *s, gint length)
{
  if (NULL == s)
  {
    return NULL;
  }
  if (length < 0)
  {
    length = strlen(s);
  }
  while(length && (s[length - 1] == '\r' || s[length - 1] == '\n'))
  {
    s[--length] = 0;
  }
  return s;
}

gint
UtilsExec(zlog_category_t *zc, const gchar *fmt, ...)
{
  va_list args;
  gchar cmd[1024];
  gint count;
  sighandler_t old_handler;
  int ret;

  va_start(args, fmt);
  count = vsnprintf(cmd, sizeof(cmd) - 1, fmt, args);
  va_end(args);

  g_assert((count > 0) && (count < sizeof(cmd)));

  if ( zc )
  {
    zlog_notice(zc, "exec: %s\n", cmd);
  }
  old_handler = signal(SIGCHLD, SIG_DFL);
  ret = system(cmd);
  signal(SIGCHLD, old_handler);

  if (zc && (ret < 0))
  {
    zlog_error(zc, "exec failed: %s\n", strerror(errno));
  }
  if ( ret )
  {
    if(zc && WIFEXITED(ret)) // 取得 cmd 执行结果
    {
      zlog_warn(zc, "Normal termination, exit code = %d\n", WEXITSTATUS(ret));
    }
    else if(zc && WIFSIGNALED(ret)) // 如果 cmd 被信号中断，取得信号值
    {
      zlog_warn(zc, "Abnormal termination, signal = %d\n", WTERMSIG(ret));
    }
    else if(zc && WIFSTOPPED(ret)) // 如果 cmd 被信号暂停执行，取得信号值
    {
      zlog_warn(zc, "Process stopped, signal = %d\n", WSTOPSIG(ret));
    }
  }
  return ret;
}

gchar*
UtilsPopen(const gchar *command)
{
  FILE *f;
  GIOChannel *ch;
  gchar *line = NULL;

  f = popen(command, "r");
  if (NULL == f)
  {
    g_warning("UtilsPopen: %s (%s)", command, strerror(errno));
    return NULL;
  }
  else
  {
    ch = g_io_channel_unix_new(fileno(f));
    g_io_channel_read_to_end(ch, &line, NULL, NULL);
    g_io_channel_unref(ch);
    pclose(f);
    return g_strdup(UtilsStripCRLF(line, -1));
  }
}

void
UtilsPopenForEach(const gchar *command, utils_popen_for_each_cb_t cb, void *param)
{
  int i;
  FILE *f;
  gchar line[1024];

  f = popen(command, "r");
  if (NULL == f)
  {
    g_warning("UtilsPopenForEach: %s (%s)", command, strerror(errno));
    return;
  }
  while(fgets(line, sizeof(line), f))
  {
    cb(UtilsStripCRLF(line, -1), param);
  }
  pclose(f);
}

gchar*
UtilsReadFileAsString(const gchar *path, const gchar *file)
{
  gchar *filename;
  GIOChannel *ch;
  gchar *line = NULL;
  gsize length;

  filename = g_strdup_printf("%s/%s", path, file);
  ch = g_io_channel_new_file(filename, "r", NULL);
  g_free(filename);
  if (NULL == ch)
  {
    return NULL;
  }
  g_io_channel_read_line(ch, &line, &length, NULL, NULL);
  g_io_channel_unref(ch);
  return UtilsStripCRLF(line, -1);;
}

guint
UtilsReadFileAsInt(const gchar *path, const gchar *file, guint default_value)
{
  guint retval;
  gchar *line;

  line = UtilsReadFileAsString(path, file);
  retval = (NULL == line) ? default_value : atoi(line);
  g_free(line);
  return retval;
}

guint
UtilsReadFileAsHex(const gchar *path, const gchar *file, guint default_value)
{
  guint retval = default_value;
  gchar *line;

  line = UtilsReadFileAsString(path, file);
  if ( line )
  {
    sscanf(line, "%x", &retval);
  }
  return retval;
}

ssize_t
UtilsSafeRead(int fd, void *buf, size_t count)
{
  ssize_t n;

  do
  {
    n = read(fd, buf, count);
  }
  while (n < 0 && errno == EINTR);

  return n;
}

/*
 * Read all of the supplied buffer from a file.
 * This does multiple reads as necessary.
 * Returns the amount read, or -1 on an error.
 * A short read is returned on an end of file.
 */
ssize_t
UtilsFullRead(int fd, void *buf, size_t len)
{
  ssize_t cc;
  ssize_t total;

  total = 0;

  while (len)
  {
    cc = UtilsSafeRead(fd, buf, len);

    if (cc < 0)
    {
      if (total)
      {
        /* we already have some! */
        /* user can do another read to know the error code */
        return total;
      }
      return cc; /* read() returns -1 on failure. */
    }
    if (cc == 0)
    {
      break;
    }
    buf = ((char *)buf) + cc;
    total += cc;
    len -= cc;
  }
  return total;
}

ssize_t
UtilsSafeWrite(int fd, const void *buf, size_t count)
{
  ssize_t n;

  do
  {
    n = write(fd, buf, count);
  }
  while (n < 0 && errno == EINTR);

  return n;
}

/*
 * Write all of the supplied buffer out to a file.
 * This does multiple writes as necessary.
 * Returns the amount written, or -1 on an error.
 */
ssize_t
UtilsFullWrite(int fd, const void *buf, size_t len)
{
  ssize_t cc;
  ssize_t total;

  total = 0;

  while (len)
  {
    cc = UtilsSafeWrite(fd, buf, len);

    if (cc < 0)
    {
      if (total)
      {
        /* we already wrote some! */
        /* user can do another write to know the error code */
        return total;
      }
      return cc;  /* write() returns -1 on failure. */
    }

    total += cc;
    buf = ((const char *)buf) + cc;
    len -= cc;
  }
  return total;
}

gchar*
UtilsReadAll(gint fd, gsize *out_len)
{
  GString *str;
  gchar buf[64];
  gssize num_read;

  str = g_string_new (NULL);

  do
  {
    num_read = read (fd, buf, sizeof (buf));
    if (num_read == -1)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        continue;
      }
      goto error;
    }
    else if (num_read > 0)
    {
      g_string_append_len(str, buf, num_read);
    }
    else if (num_read == 0)
    {
      break;
    }
  }
  while (TRUE);

  if (out_len != NULL)
  {
    *out_len = str->len;
  }
  return g_string_free(str, FALSE);

error:
  if (out_len != NULL)
  {
    out_len = 0;
  }
  g_string_free(str, TRUE);
  return NULL;
}

gboolean
UtilsWriteAll(gint fd, gconstpointer vbuf, gsize to_write)
{
  gchar *buf = (gchar *) vbuf;

  while(to_write > 0)
  {
    gssize count = write (fd, buf, to_write);

    if (count < 0)
    {
      if (errno != EINTR)
      {
        return FALSE;
      }
    }
    else
    {
      to_write -= count;
      buf += count;
    }
  }
  return TRUE;
}

gchar*
UtilsCheckMount(const gchar *device_name)
{
  FILE *f;
  struct mntent *mnt;
  gchar *mnt_dir = NULL;

  if ((f = setmntent(MOUNTED, "r")) == NULL)
  {
    return NULL;
  }
  while ((mnt = getmntent(f)) != NULL)
  {
    if (strcmp(device_name, mnt->mnt_fsname) == 0)
    {
      mnt_dir = g_strdup(mnt->mnt_dir);
      break;
    }
  }
  endmntent(f);

  return mnt_dir;
}

//==============================================================================

gint
UtilsDaemonKill(gchar *ident)
{
  gint ret;

  /* Set indetification string for the daemon for both syslog and PID file */
  daemon_pid_file_ident = daemon_log_ident = daemon_ident_from_argv0(ident);

  /* Kill daemon with SIGTERM */

  /* Check if the new function daemon_pid_file_kill_wait() is available, if it is, use it. */
  if ((ret = daemon_pid_file_kill_wait(SIGTERM, 5)) < 0)
  {
    daemon_log(LOG_WARNING, "Failed to kill daemon: %s", strerror(errno));
  }

  return ret < 0 ? 1 : 0;
}

gint
UtilsDaemonStart(gchar *ident)
{
  pid_t pid;

  /* Reset signal handlers */
  if (daemon_reset_sigs(-1) < 0)
  {
    daemon_log(LOG_ERR, "Failed to reset all signal handlers: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Unblock signals */
  if (daemon_unblock_sigs(-1) < 0)
  {
    daemon_log(LOG_ERR, "Failed to unblock all signals: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Set indetification string for the daemon for both syslog and PID file */
  daemon_pid_file_ident = daemon_log_ident = daemon_ident_from_argv0(ident);

  /* Check that the daemon is not rung twice a the same time */
  if ((pid = daemon_pid_file_is_running()) >= 0)
  {
    daemon_log(LOG_ERR, "Daemon already running on PID file %u", pid);
    exit(EXIT_FAILURE);
  }

  /* Prepare for return value passing from the initialization procedure of the daemon process */
  if (daemon_retval_init() < 0)
  {
    daemon_log(LOG_ERR, "Failed to create pipe.");
    exit(EXIT_FAILURE);
  }

  /* Do the fork */
  if ((pid = daemon_fork()) < 0)
  {
    /* Exit on error */
    daemon_retval_done();
    exit(EXIT_FAILURE);
  }
  else if (pid)     /* The parent */
  {
    int ret;

    /* Wait for 20 seconds for the return value passed from the daemon process */
    if ((ret = daemon_retval_wait(20)) < 0)
    {
      daemon_log(LOG_ERR, "Could not recieve return value from daemon process: %s", strerror(errno));
      exit(-1);
    }

    daemon_log(ret != 0 ? LOG_ERR : LOG_INFO, "Daemon returned %i as return value.", ret);

    exit(ret);
  }
  else     /* The daemon */
  {
    int fd, quit = 0;
    fd_set fds;

    /* Close FDs */
    if (daemon_close_all(-1) < 0)
    {
      daemon_log(LOG_ERR, "Failed to close all file descriptors: %s", strerror(errno));

      /* Send the error condition to the parent process */
      daemon_retval_send(1);
      return -1;
    }

    /* Create the PID file */
    if (daemon_pid_file_create() < 0)
    {
      daemon_log(LOG_ERR, "Could not create PID file (%s).", strerror(errno));
      daemon_retval_send(2);
      return -1;
    }

    /*... do some further init work here */


    /* Send OK to parent process */
    daemon_retval_send(0);

    daemon_log(LOG_INFO, "Sucessfully started");

    return 0;
  }
}

void
UtilsDaemonStop(void)
{
  daemon_log(LOG_INFO, "Exiting...");
  daemon_retval_send(255);
  daemon_signal_done();
  daemon_pid_file_remove();
}

void
UtilsDaemonLog(int prio, const char* template, ...)
{
  va_list arglist;

  va_start(arglist, template);
  daemon_logv(prio, template, arglist);
  va_end(arglist);
}

//==============================================================================

gboolean
UtilsMakeConnection (const char *hostname, guint16 port,
                     GCancellable     *cancellable,
                     guint             timeout,
                     gboolean          use_udp,
                     GSocket         **socket,
                     GSocketAddress  **address,
                     GError          **error)
{
  GSocketType socket_type;
  GSocketFamily socket_family;
  GSocketAddressEnumerator *enumerator;
  GSocketConnectable *connectable;
  GSocketAddress *src_address;
  GError *err = NULL;

  GInetAddress *addr;

  if (use_udp)
  {
    socket_type = G_SOCKET_TYPE_DATAGRAM;
  }
  else
  {
    socket_type = G_SOCKET_TYPE_STREAM;
  }
  socket_family = G_SOCKET_FAMILY_IPV4;

  *socket = g_socket_new(socket_family, socket_type, 0, error);
  if (*socket == NULL)
  {
    return FALSE;
  }
  g_socket_set_timeout(*socket, timeout);
#if 0
  addr = g_inet_address_new_from_string(hostname);
  *address = g_inet_socket_address_new(addr, port);
  g_socket_connect(*socket, *address, cancellable, &err);
  g_clear_error(&err);
#else
  connectable = g_network_address_new(hostname, port);
  if (connectable == NULL)
  {
    return FALSE;
  }
  enumerator = g_socket_connectable_enumerate(connectable);
  while (TRUE)
  {
    *address = g_socket_address_enumerator_next(enumerator, cancellable, error);
    if (*address == NULL)
    {
      if (error != NULL && *error == NULL)
      {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                            "No more addresses to try");
      }
      return FALSE;
    }

    if (g_socket_connect(*socket, *address, cancellable, &err))
    {
      break;
    }
    //g_message("Connection to %s failed: %s, trying next\n", socket_address_to_string (*address), err->message);
    g_clear_error(&err);

    g_object_unref(*address);

    if (cancellable && g_cancellable_is_cancelled(cancellable))
    {
      break;
    }
  }
  g_object_unref(enumerator);
#endif
  if (cancellable && g_cancellable_is_cancelled(cancellable))
  {
    return FALSE;
  }

  //g_print("Connected to %s\n", socket_address_to_string(*address));

  src_address = g_socket_get_local_address(*socket, error);
  if (!src_address)
  {
    g_prefix_error(error, "Error getting local address: ");
    return FALSE;
  }

  //g_print("local address: %s\n", socket_address_to_string(src_address));
  g_object_unref(src_address);
  g_object_unref(connectable);

  return TRUE;
}

gboolean
UtilsCreateThread(pthread_t *thread, int priority,
  void *(*routine)(void *), void *arg)
{
  pthread_attr_t attr;
  struct sched_param schedParam;

  if ( pthread_attr_init(&attr) )
  {
    return FALSE;
  }
  if ( pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM) )
  {
    return FALSE;
  }
  if ( pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) )
  {
    return FALSE;
  }
  if ( pthread_attr_setschedpolicy(&attr, SCHED_FIFO) )
  {
    return FALSE;
  }
  schedParam.sched_priority = priority;
  if ( pthread_attr_setschedparam(&attr, &schedParam) )
  {
    return FALSE;
  }
  if ( pthread_create(thread, &attr, routine, arg) )
  {
    return FALSE;
  }
  pthread_attr_destroy(&attr);  
  return TRUE;
}

//==============================================================================

typedef struct
{
  void (*handler)(void *param);
  void *param;
} utils_work_t;

static GThreadPool *utils_work_pool;

static void
utils_work_process(gpointer data, gpointer user_data)
{
  utils_work_t *work = data;

  work->handler(work->param);
  g_free(work);
}

void
UtilsPostWork(void (*handler)(void *param), void *param)
{
  static gsize initialised;

  utils_work_t *work;

  if (g_once_init_enter (&initialised))
  {
    utils_work_pool = g_thread_pool_new(utils_work_process, NULL, 16, TRUE, NULL);
    g_once_init_leave (&initialised, TRUE);
  }
  work = g_new(utils_work_t, 1);
  g_assert(work);
  work->handler = handler;
  work->param = param;
  g_thread_pool_push(utils_work_pool, work, NULL);
}

//==============================================================================

gboolean
UtilsGetMac(const gchar *name, guint8 *mac)
{
  int sock;
  struct ifreq ifreq;
  
  if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    return FALSE;
  }
  strcpy(ifreq.ifr_name, name);
  if(ioctl(sock, SIOCGIFHWADDR, &ifreq) < 0)
  {
    close(sock);
    return FALSE;
  }
  memcpy(mac, ifreq.ifr_hwaddr.sa_data, 6);
  close(sock);
  return TRUE;
}

// How to correctly judge the keyframe of H.264
// http://e2e.ti.com/support/embedded/multimedia_software_codecs/f/356/t/73235.aspx
gboolean
UtilsH264IsKeyFrame(guint8 *data)
{
  const char data1[] = {00, 00, 00, 01, 0x67, 0x64};
  const char data2[] = {00, 00, 00, 01, 0x27, 0x64};
  const char data3[] = {00, 00, 00, 01, 0x61, 0x88};

  return (memcmp(data, data1, 6) == 0 || 
    memcmp(data, data2, 6) == 0 || 
    memcmp(data, data3, 6) == 0);
}

// 参考 http://www.gnu.org/software/libc/manual/html_node/Backtraces.html
void
UtilsBacktrace(zlog_category_t *zc)
{
  size_t i, size;
  void *array[10];
  char **strings;
  
  size = backtrace(array, 10);
  strings = backtrace_symbols(array, size);
  zlog_info(zc, "=================== stack frames: %zd\n", size);
  for(i = 0; i < size; i++)
  {
    zlog_info(zc, "%s\n", strings[i]);
  }
  zlog_info(zc, "=================== stack frames end\n");  
  free(strings);
}

