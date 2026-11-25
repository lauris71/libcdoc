// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <cdoc/CDoc.h>

namespace libcdoc
{

/**
 * @brief Generic interface to implement a logger.
 */
class CDOC_EXPORT Logger
{
public:
    virtual ~Logger() noexcept = default;

    /**
     * @brief Logs given message with given severity, file name and line number.
     * 
     * It tests the log level and if <= min_level invokes logMessage
     * 
     * @param level Severity of the log message.
     * @param file File name where the log message was recorded.
     * @param line Line number in the file where the log message was recorded.
     * @param msg The log message.
     */
    void log(LogLevel level, std::string_view file, int line, std::string_view msg) {
        if (level <= min_level) logMessage(level, file, line, msg);
    }

    /**
     * @brief Sets minimum log level for the logger.
     * @param level minimum level to log.
     *
     * Sets minimum level of log messages to log. For example, if the minimum log level is set
     * to LEVEL_INFO (default), then LEVEL_FATAL, LEVEL_ERROR, LEVEL_WARNING and LEVEL_INFO
     * messages are logged, but not LEVEL_DEBUG or LEVEL_TRACE messages.
     */
    constexpr void setMinLogLevel(LogLevel level) noexcept { min_level = level; }

protected:
    /**
     * @brief Logs given message with given severity, file name and line number.
     * 
     * Every class implementing the ILogger interface must implement this member function.
     * The efault implementation does nothing.
     * The level should be checked by caller, thus the implementation should expect that level <= min_level
     * 
     * @param level Severity of the log message.
     * @param file File name where the log message was recorded.
     * @param line Line number in the file where the log message was recorded.
     * @param msg The log message.
     */
    virtual void logMessage(LogLevel level, std::string_view file, int line, std::string_view msg) {}

    /**
     * @brief Minimum level of log messages to log.
     */
    LogLevel min_level = LEVEL_WARNING;
};

}
