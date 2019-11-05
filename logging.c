#define _ISOC99_SOURCE
#define _POSIX_C_SOURCE 200809
#include <pthread.h>
#include <sys/time.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>

#include "logging.h"

static FILE *LOGFILE = NULL;
static int LOGFILE_ISATTY = 0;
static pthread_once_t once = PTHREAD_ONCE_INIT;

void init_logging()
{
    LOGFILE = stdout;
    if (isatty(fileno(LOGFILE)))
        LOGFILE_ISATTY = 1;
}

const char *level2str(int level)
{
    switch (level) {
    case DEBUG: return "DEBUG";
    case INFO: return "INFO";
    case WARN: return "WARN";
    case ERROR: return "ERROR";
    default: return "?";
    }
}

const char *level2color(int level)
{
    switch (level) {
    case DEBUG: return "\x1B[90m";   /* gray   */
    case INFO: return "";            /* normal  */
    case WARN: return "\x1B[33m";    /* yellow */
    case ERROR: return "\x1B[31m";   /* red    */
    default: return "\x1B[31m";      /* red    */
    }
}


/* format timeval like: 2019-10-02 14:25:59.264
 * make sure len >= 24
 */
char* strftimeval(const struct timeval *tv, char *s, size_t len)
{
    if (len < 24)
        return NULL;

    struct tm tm;
    localtime_r(&tv->tv_sec, &tm);

    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    int millisec = tv->tv_usec / 1000;
    snprintf(s, len, "%s.%03d", buf, millisec);
    return s;
}


void ymlog(int level, const char *file, int line, const char *func, const char *fmt, ...)
{
    pthread_once(&once, init_logging);

    struct timeval now;
    char nowstr[32];
    gettimeofday(&now, NULL);
    strftimeval(&now, nowstr, sizeof(nowstr));

    const char *levelstr = level2str(level);
    const char *color = LOGFILE_ISATTY ? level2color(level) : "";
    const char *color_reset = LOGFILE_ISATTY ? "\x1B[0m" : "";
    /* color[now level file:line func()] msg.... color_reset*/
    fprintf(LOGFILE, "%s[%s %s %s:%d %s()] ", color, nowstr, levelstr, file, line, func);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(LOGFILE, fmt, ap);
    fprintf(LOGFILE, "%s\n", color_reset);
}
