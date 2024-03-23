package logger

import (
	"fmt"
	"time"
)

func log(logType, message string) {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[ %s | %s ]: %s\n", currentTime, logType, message)
}

func Err(message string) {
	log("ERROR", message)
}

func Debug(message string) {
	log("DEBUG", message)
}

func Info(message string) {
	log("INFO ", message)
}
