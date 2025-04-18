package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
	Hostname  string    `json:"hostname"`
}

type SyslogLine struct {
	Beat      bool   `json:"beat"`
	Timestamp string `json:"timestamp"`
	Hostname  string `json:"hostname"`
	Program   string `json:"program"`
	Pid       string `json:"pid"`
	Message   string `json:"message"`
}

var (
	logfile = flag.String("log", "logs.ndjson", "Path to the log file")
	addr    = flag.String("addr", ":8081", "Address to listen on")
	rotate  = flag.Bool("rotate", false, "Rotate log file")
	logSize = flag.Int("size", 100, "Max size of log file in MB")
)

func rotateLog(filename string, maxSizeMB int) error {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return err
	}

	fileSizeMB := fileInfo.Size() / (1024 * 1024)
	if int(fileSizeMB) >= maxSizeMB {
		timestamp := time.Now().Format("20060102150405")
		rotatedFilename := filename + "." + timestamp

		err := os.Rename(filename, rotatedFilename)
		if err != nil {
			return err
		}

		log.Printf("Rotated log file to: %s", rotatedFilename)
	}
	return nil
}

func handleLog(conn quic.Connection) {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("Error accepting stream: %v", err)
		return
	}
	defer stream.Close()

	decoder := json.NewDecoder(stream) // Create decoder once

	for { // Loop to process multiple JSON objects
		var sl SyslogLine
		err := decoder.Decode(&sl)
		if err != nil {
			if err.Error() == "EOF" {
				break // End of stream
			}
			log.Printf("Error decoding JSON: %v", err)
			return // Or continue if you want to skip bad JSON
		}
		if sl.Beat {
			_, err := stream.Write([]byte(`{"status":"beat_ok"}`))
			if err != nil {
				log.Printf("Error writing beat response: %v", err)
				return
			}
			continue // Skip if it's a beat message
		}

		logEntry := LogEntry{
			Timestamp: time.Now(),
			Message:   sl.Message,
			Hostname:  sl.Hostname,
		}

		jsonData, err := json.Marshal(logEntry)
		if err != nil {
			log.Printf("Error marshalling JSON: %v", err)
			return
		}

		go func() {
			if *rotate {
				if err := rotateLog(*logfile, *logSize); err != nil {
					log.Printf("Error rotating log: %v", err)
				}
			}

			file, err := os.OpenFile(*logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Printf("Error opening file: %v", err)
				return
			}
			defer file.Close()

			_, err = file.WriteString(string(jsonData) + "\n")
			if err != nil {
				log.Printf("Error writing to file: %v", err)
			}
		}()

		_, err = stream.Write([]byte(`{"status":"ok"}`))
		if err != nil {
			log.Printf("Error writing response: %v", err)
			return // or continue
		}
	}
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA key: %v", err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("Error creating certificate: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("Error creating key pair: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}, NextProtos: []string{"quic-log-protocol"}}
}

func main() {
	flag.Parse()
	tlsConf := generateTLSConfig()

	listener, err := quic.ListenAddr(*addr, tlsConf, nil)
	if err != nil {
		log.Fatalf("Error listening: %v", err)
	}
	defer listener.Close()

	fmt.Println("QUIC server listening on", *addr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleLog(conn)
	}
}
