#include "../ft_nmap.h"

typedef enum { LOG_INFO, LOG_WARN, LOG_ERROR } LogLevel;

// Convert log level to string
const char* log_level_to_string(LogLevel level) {
    switch (level) {
        case LOG_INFO: return "INFO";
        case LOG_WARN: return "WARNING";
        case LOG_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

// Logger function
void log_message(LogLevel level, const char* format, ...) {
    FILE* log_file = fopen("log.txt", "a");  // Open log file in append mode
    if (!log_file) {
        perror("Failed to open log file");
        return;
    }

    // Get current time
    time_t now = time(NULL);
    struct tm* t = localtime(&now);

    // Print timestamp and log level
    fprintf(log_file, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] ",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec,
            log_level_to_string(level));

    // Handle variable arguments
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fprintf(log_file, "\n");
    fclose(log_file);
}
