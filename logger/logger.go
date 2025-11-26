package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
)

type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
	NONE
)

type Logger struct {
	level Level
}

var globalLogger = &Logger{level: INFO}

func SetLevel(level Level) {
	globalLogger.level = level
}

func SetLevelFromString(levelStr string) error {
	levelStr = strings.ToUpper(levelStr)
	switch levelStr {
	case "DEBUG":
		globalLogger.level = DEBUG
	case "INFO":
		globalLogger.level = INFO
	case "WARN":
	case "WARNING":
		globalLogger.level = WARN
	case "ERROR":
		globalLogger.level = ERROR
	case "NONE":
		globalLogger.level = NONE
	default:
		return fmt.Errorf("invalid log level: %s", levelStr)
	}
	return nil
}

func GetLevel() Level {
	return globalLogger.level
}

func IsDebugEnabled() bool {
	return globalLogger.level <= DEBUG
}

func Debug(v ...interface{}) {
	if globalLogger.level <= DEBUG {
		log.Println("[DEBUG]", fmtArgs(v...))
	}
}

func Debugf(format string, v ...interface{}) {
	if globalLogger.level <= DEBUG {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func Info(v ...interface{}) {
	if globalLogger.level <= INFO {
		log.Println("[INFO]", fmtArgs(v...))
	}
}

func Infof(format string, v ...interface{}) {
	if globalLogger.level <= INFO {
		log.Printf("[INFO] "+format, v...)
	}
}

func Warn(v ...interface{}) {
	if globalLogger.level <= WARN {
		log.Println("[WARN]", fmtArgs(v...))
	}
}

func Warnf(format string, v ...interface{}) {
	if globalLogger.level <= WARN {
		log.Printf("[WARN] "+format, v...)
	}
}

func Error(v ...interface{}) {
	if globalLogger.level <= ERROR {
		log.Println("[ERROR]", fmtArgs(v...))
	}
}

func Errorf(format string, v ...interface{}) {
	if globalLogger.level <= ERROR {
		log.Printf("[ERROR] "+format, v...)
	}
}

func Fatal(v ...interface{}) {
	log.Println("[FATAL]", fmtArgs(v...))
	os.Exit(1)
}

func Fatalf(format string, v ...interface{}) {
	log.Printf("[FATAL] "+format, v...)
	os.Exit(1)
}

func fmtArgs(v ...interface{}) string {
	var result string
	for i, arg := range v {
		if i > 0 {
			result += " "
		}
		result += formatValue(arg)
	}
	return result
}

func formatValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case error:
		return val.Error()
	default:
		return fmt.Sprintf("%v", val)
	}
}
