package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/pion/dtls/v2"
)

func main() {
	hexData := flag.String("data", "", "data to parse")
	flag.Parse()

	data, err := hex.DecodeString(*hexData)
	if err != nil {
		log.Fatal(err)
	}

	records, err := dtls.Decode(data)
	if err != nil {
		log.Fatal(err)
	}

	s, _ := json.MarshalIndent(records, "", "\t")
	fmt.Println(string(s))
}
