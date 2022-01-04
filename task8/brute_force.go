package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"golang.org/x/crypto/nacl/secretbox"
)

// Message holds the nonce, ciphertext, and timestamp of an encrypted message.
type Message struct {
	Nonce      *[24]byte
	Ciphertext []byte
	Timestamp  int
}

var (
	// username_file holds the username list to try
	username_file = "names.txt"
	// messages is a global Message slice for sharing messages across goroutines.
	messages []Message
	// timestamps holds timestamps of the init message from three different listening post sessions.
	timestamps = []int{1615897639, 1615897678, 1615897728}
	// packets holds hexdumps of packet data from three different listening post sessions.
	packets = []string{
		"6ff290588db134c030a69b63d6319c71d2c35af189cdf55da76eb48ecc9b38ab27f0cf897a2448326cb4b448b716d34ffe7cd9fd215eea31933dce9d50cc042f283d2adc06eb8e0d28c135e621f0",
		"30ebcf5f20a6d7d06d31c233560d18f13330be17ff8e896c5d61fde2644345cc997c9c627494423b042d545bf6f102a7f10f9b5856c83f49553d1a9cd0661c0d56b435459b046e571f488321f56c",
		"f5560af46f120876788160addb65aeb3cf365b038567a0302dcb0b377dd70873087e773db76687ce213db432d12c893437bb93a71900c423d707c118695fbd74bd45a713a2f09e1bff87da54e3e9",
	}
)

// Populate global messages slice on init.
func init() {
	for i, p := range packets {
		// Decode packet data.
		e, _ := hex.DecodeString(p)

		// Nonce data.
		nonce := (*[24]byte)(e[4:28])

		// Ciphertext data.
		ciphertext := e[28:]

		// Create struct and add to messages.
		messages = append(messages, Message{
			Nonce:      nonce,
			Ciphertext: ciphertext,
			Timestamp:  timestamps[i],
		})
	}
}

func main() {
	// Open username file.
	file, _ := os.Open(username_file)
	defer file.Close()
	scanner := bufio.NewScanner(file)

	// Setup benchmarking variables.
	usernameCount := 0
	checkpoint := time.Now().UnixMilli()
	currentTime := checkpoint
	diff := currentTime - checkpoint

	// CPU count determines how many consumers we make.
	fmt.Println("CPU Count:", runtime.NumCPU())

	// Make channel for passing usernames to consumers
	userChan := make(chan string)

	// Make consumer routine for each CPU.
	for i := 0; i < runtime.NumCPU(); i++ {
		go testUsername(userChan)
	}

	// Make and start spinner.
	start := time.Now()
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	s.Suffix = fmt.Sprintf(" Usernames/Second: %3.3f, Time Elapsed: %v", 0.0, time.Since(start))
	s.Color("yellow")
	s.Start()
	defer s.Stop()

	// Iterate over every username in username file.
	for scanner.Scan() {
		// New username.
		username := strings.ToLower(scanner.Text())

		// Send username to goroutines.
		userChan <- username

		// Benchmark every 100 usernames
		if usernameCount%100 == 0 && usernameCount != 0 {
			currentTime = time.Now().UnixMilli()

			diff = currentTime - checkpoint

			// Don't divide by zero.
			if diff == 0 {
				diff = 1
			}

			wps := (100.0 * 1000.0) / float32(diff)

			// Update metrics.
			s.Suffix = fmt.Sprintf(" Usernames/Second: %3.3f, Time Elapsed: %v", wps, time.Since(start))

			checkpoint = currentTime
		}

		usernameCount++
	}
}

// For each word, test every:
// Version from 0.0.0.0 to 9.9.9.9 and
// Timestamp from timestamp-1 to timestamp+1
// for each message.
func testUsername(userChan chan string) {
	var u string
	for {
		u = <-userChan
		for v1 := 0; v1 < 10; v1++ {
			for v2 := 0; v2 < 10; v2++ {
				for v3 := 0; v3 < 10; v3++ {
					for v4 := 0; v4 < 10; v4++ {
						for i, m := range messages {
							for t := m.Timestamp - 1; t <= m.Timestamp+1; t++ {
								k := fmt.Sprintf("%s+%d.%d.%d.%d+%d", u, v1, v2, v3, v4, t)
								key := sha256.Sum256([]byte(k))
								if _, ok := secretbox.Open(nil, m.Ciphertext, m.Nonce, &key); ok {
									info := color.New(color.FgGreen).PrintfFunc()
									info("\n[+] %s\n", k)
									// Remove message from list, probably safe *shrug*.
									messages[i] = messages[len(messages)-1]
									messages = messages[:len(messages)-1]
								}

							}
						}
					}
				}
			}
		}
	}
}
