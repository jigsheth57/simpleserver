package main

import (
	"crypto/tls"
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte("This is an example server.\n"))
	})
	serverCert, _ := tls.LoadX509KeyPair("server.crt", "server.key")
	var ciphersuite map[uint16]string
	ciphersuite = make(map[uint16]string)
	ciphersuite[tls.TLS_RSA_WITH_RC4_128_SHA] = "TLS_RSA_WITH_RC4_128_SHA"
	ciphersuite[tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	ciphersuite[tls.TLS_RSA_WITH_AES_128_CBC_SHA] = "TLS_RSA_WITH_AES_128_CBC_SHA"
	ciphersuite[tls.TLS_RSA_WITH_AES_256_CBC_SHA] = "TLS_RSA_WITH_AES_256_CBC_SHA"
	ciphersuite[tls.TLS_RSA_WITH_AES_128_CBC_SHA256] = "TLS_RSA_WITH_AES_128_CBC_SHA256"
	ciphersuite[tls.TLS_RSA_WITH_AES_128_GCM_SHA256] = "TLS_RSA_WITH_AES_128_GCM_SHA256"
	ciphersuite[tls.TLS_RSA_WITH_AES_256_GCM_SHA384] = "TLS_RSA_WITH_AES_256_GCM_SHA384"
	ciphersuite[tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA] = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	ciphersuite[tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	ciphersuite[tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	ciphersuite[tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA] = "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	ciphersuite[tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA] = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	ciphersuite[tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	ciphersuite[tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	ciphersuite[tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	ciphersuite[tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	ciphersuite[tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	ciphersuite[tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	ciphersuite[tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	ciphersuite[tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	ciphersuite[tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
	ciphersuite[tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
	// TLS 1.3 cipher suites.
	ciphersuite[tls.TLS_AES_128_GCM_SHA256] = "TLS_AES_128_GCM_SHA256"
	ciphersuite[tls.TLS_AES_256_GCM_SHA384] = "TLS_AES_256_GCM_SHA384"
	ciphersuite[tls.TLS_CHACHA20_POLY1305_SHA256] = "TLS_CHACHA20_POLY1305_SHA256"
	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See RFC 7507.
	ciphersuite[tls.TLS_FALLBACK_SCSV] = "TLS_FALLBACK_SCSV"

	cfg := &tls.Config{
		MinVersion:               tls.VersionSSL30,
		CurvePreferences:         []tls.CurveID{tls.X25519,tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			log.Println("Client Supported Elliptic Curve:")
			for i := range hi.SupportedCurves {
				log.Printf("==> %x\n", hi.SupportedCurves[i])
			}
			log.Println("Client Supported Protocols:")
			for i := range hi.SupportedProtos {
				log.Println("==> "+hi.SupportedProtos[i])
			}
			log.Println("Client Supported SSL Version:")
			for i := range hi.SupportedVersions {
				log.Printf("==> %x\n", hi.SupportedVersions[i])
			}
			log.Println("Client Supported Cipher Suite:")
			log.Println("Note: for any hex value, server is not configured for it. You can get the value using 'openssl ciphers -v -V'")
			for i := range hi.CipherSuites {
				value, ok := ciphersuite[hi.CipherSuites[i]]
				if ok {
					log.Println("==> "+value)
				} else {
					// lookup the value via "openssl ciphers -v -V" using hex
					log.Printf("==> %x\n", hi.CipherSuites[i])
				}
			}
			serverConf := &tls.Config{
				Certificates: []tls.Certificate{serverCert},
				MinVersion:            tls.VersionSSL30,
				ClientAuth:            tls.NoClientCert,
			}
			return serverConf, nil
		},
		CipherSuites: []uint16{
			// TLS 1.0 - 1.2 cipher suites.
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			// TLS 1.3 cipher suites.
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
			// that the client is doing version fallback. See RFC 7507.
			tls.TLS_FALLBACK_SCSV,
		},
	}
	srv := &http.Server{
		Addr:         ":8443",
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	log.Fatal(srv.ListenAndServeTLS("server.crt", "server.key"))
}