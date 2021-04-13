package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	//
	fmt.Println("wol_test")
	//
	if 3 <= len(os.Args) {
		//
		if conn, err := net.DialTimeout("tcp", os.Args[1], 3*time.Second); nil == err {
			//
			conn.Write([]byte(fmt.Sprintf(`{"cmd":"bind","key":"%s","ssid":"SSID","ip":"0.0.0.0"}`, strings.ToUpper(os.Args[2]))))
			//
			for {
				//
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				//
				io.Copy(os.Stdout, conn)
				//
				//conn.Write([]byte(`{"cmd":"beat"}`))
				conn.Write([]byte(`{"cmd":"warn"}`))
			}
		} else {
			//
			fmt.Println(err)
		}
	} else {
		//
		fmt.Printf("%s IP:PORT DEVID\n", filepath.Base(os.Args[0]))
	}
}
