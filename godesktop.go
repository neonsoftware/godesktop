package godesktop

import (
	"log"
	"os"
	"fmt"
)

var Logger *log.Logger = log.New(os.Stdout, "[main] ", log.Lshortfile)


func example() {
	fmt.Println("example")
}