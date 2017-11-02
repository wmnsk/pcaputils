package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// maybeBase64 guesses the string is Base64-formatted or not.
// As you see, normal strings can also be concluded as Base64...
// Using regexp package will do the better job, but it'll be tiresome much more :-P
func maybeBase64(s string) bool {
	gzUpper := "G | H | I | J | K | L | M | N | O | P | Q | R | S | T | U | V | W | X | Y | Z"
	gzLower := "g | h | i | j | k | l | m | n | o | p | q | r | s | t | u | v | w | x | y | z"
	if strings.ContainsAny(s, gzUpper) || strings.ContainsAny(s, gzLower) {
		return true
	}
	return false
}

func main() {
	var (
		input  = flag.String("s", "", "Hex or Base64 encoded string.")
		output = flag.String("o", "WOW.pcap", "Name of PCAP to export.")
	)
	flag.Parse()

	if *input == "" {
		flag.Usage()
		os.Exit(-1)
	}

	// Convert string into binary.
	var data []byte
	var err error
	if maybeBase64(*input) { // guess format b64 or hex.
		data, err = base64.StdEncoding.DecodeString(*input)
		if err != nil {
			log.Fatalf("Failed to decode string %s", err)
		}
	} else { // try hex.
		data, err = hex.DecodeString(*input)
		if err != nil {
			log.Fatalf("Failed to decode string %s", err)
		}
	}
	// Unexpected. This shouldn't be called.
	if data == nil {
		log.Fatalf("Hey, something went wrong in data ¯\\_(ツ)_/¯, %s", data)
	}

	// Create file to be written.
	f, err := os.Create(*output)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()

	// Setup PCAP writer.
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	// Write PCAP.
	w.WritePacket(
		gopacket.CaptureInfo{
			Timestamp:      time.Now(),
			CaptureLength:  len(data),
			Length:         len(data),
			InterfaceIndex: 0,
		},
		data,
	)
	f.Close()

	log.Printf("Successfully exported PCAP as \"%s\"", *output)
}
