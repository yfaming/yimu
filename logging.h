#ifndef LOGGING_H
#define LOGGING_H

#include <string.h>

enum log_level {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3
};

void ymlog(int level, const char *file, int line, const char *func, const char *fmt, ...);

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define debug(fmt, ...) ymlog(DEBUG, __FILENAME__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define info(fmt, ...) ymlog(INFO, __FILENAME__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define warn(fmt, ...) ymlog(WARN, __FILENAME__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define error(fmt, ...) ymlog(ERROR, __FILENAME__, __LINE__, __func__, fmt, ##__VA_ARGS__)


#endif /* ifndef LOGGING_H */
