package main

import (
        "net"
        "os"
        "fmt"
        "flag"
        "log"
        "crypto/rand"
        "crypto/tls"
)

var keyFile  = flag.String("key-file", "./tls/server/key.pem", "Server private key to use")
var certFile = flag.String("cert-file", "./tls/server/cert.pem", "Server certificate to use")

var cipherSuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA}

func main() {
        flag.Parse()

        endpoint := "127.0.0.1:14433"
        cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)

        if err != nil {
                log.Fatalf("Failed to load key or cert: %s", err)
        }
        config := tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert}
        config.Rand = rand.Reader
        // Wireshark supports these
        config.CipherSuites = cipherSuites

        bind(endpoint, &config)
}

func bind(endpoint string, tlsConfig *tls.Config) {
        listener, err := tls.Listen("tcp", endpoint, tlsConfig)
        dieOnError(err)

        fmt.Printf("Bound to %s\n", endpoint)

        for {
                conn, err := listener.Accept()

                fmt.Printf("Accepted a client from %s\n", conn.RemoteAddr().String())

                if err != nil {
                        continue
                }
                go serve(conn)
        }
}

func serve(conn net.Conn) {
        defer conn.Close()
        tlscon, ok := conn.(*tls.Conn)

        if !ok {
                log.Fatalf("Not a TLS connection!")
                os.Exit(1)
        }

        err := tlscon.Handshake()
        if err != nil {
            log.Fatalf("Handshake failed: %s", err)
        } else {
            log.Print("Handshake completed")
        }

        state := tlscon.ConnectionState()

        log.Println("Client public key is:")
        for _, v := range state.PeerCertificates {
            log.Print(v.PublicKey)
        }

        log.Printf("Negotiated protocol: %s, mutual?: %t\n", state.NegotiatedProtocol, state.NegotiatedProtocolIsMutual)

        var buf [4096]byte

        for {
                n, err := conn.Read(buf[0:])
                if err != nil {
                        log.Printf("Done serving %s\n", conn.RemoteAddr().String())
                        return
                }
                s := string(buf[0:])
                log.Printf("Received: %s\n", s)

                _, err2 := conn.Write(buf[0:n])
                if err2 != nil {
                        log.Printf("Done serving %s\n", conn.RemoteAddr().String())
                        return
                }
        }
}

func dieOnError(err error) {
        if err != nil {
                log.Fatalf("Fatal error: %s", err.Error())
                os.Exit(1)
        }
}