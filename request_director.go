package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"

	log "github.com/Sirupsen/logrus"
)

type RequestDirector struct {
	port      string
	sshServer *SSHServer
}

func (director *RequestDirector) Start() {
	log.Info("Starting Request director...")

	listener, err := net.Listen("tcp", ":"+director.port)
	if err != nil {
		log.Fatalf("Could not listen on port %s: %s", director.port, err)
	}

	log.Infof("Request director listening on port %s", director.port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Warnf("Could not accept connection: %s", err)
			continue
		}

		go director.handleConn(conn)
	}
}

func (director *RequestDirector) handleConn(conn net.Conn) {
	var connBuf bytes.Buffer
	connReader := io.TeeReader(conn, &connBuf)

	httpRequest, err := http.ReadRequest(bufio.NewReader(connReader))
	if err != nil {
		log.WithFields(log.Fields{
			"remote_ip": conn.RemoteAddr(),
		}).Warnf("Couldn't parse request as HTTP: %s", err)

		if err := conn.Close(); err != nil {
			log.Warnf("Could not close request", err)
		}

		return
	}

	domain := httpRequest.Host

	contextLogger := log.WithFields(log.Fields{
		"remote_ip":          conn.RemoteAddr(),
		"destination_domain": domain,
		"destination_path":   httpRequest.URL.Path,
	})

	contextLogger.Info("Incoming request")

	if director.port != "80" {
		domain, _, err = net.SplitHostPort(domain)
		if err != nil {
			contextLogger.Warnf("Could not split host and port: %s", err)
		}
	}

	tun, err := director.findTunnel(domain)
	if err != nil {
		contextLogger.Info(err)
		director.handle404(conn)
		return
	}

	sshChannel, err := director.sshServer.createChannel(*tun)
	if err != nil {
		contextLogger.Warnf("Couldn't create a tunnel for: http://%s", domain)

		director.handle404(conn)
		return
	}

	go func() {
		_, err := io.Copy(sshChannel, &connBuf)
		if err != nil {
			contextLogger.Warnf("Couldn't copy request to tunnel: %s", err)
			return
		}

		if err = sshChannel.CloseWrite(); err != nil {
			contextLogger.Warnf("Could not close SSH channel: %s", err)
		}

		_, err = io.Copy(conn, sshChannel)
		if err != nil {
			contextLogger.Warnf("Couldn't copy response from tunnel: %s", err)
			return
		}

		contextLogger.Info("Returned response")

		if err = conn.Close(); err != nil {
			contextLogger.Warnf("Could not close request: %s", err)
		}
	}()
}

func (director *RequestDirector) findTunnel(domain string) (*Tunnel, error) {
	director.sshServer.RLock()
	tun := director.sshServer.tunnels[domain]
	director.sshServer.RUnlock()

	if tun == nil {
		return nil, fmt.Errorf("No tunnel found for %s", domain)
	}

	return tun, nil
}

func (director *RequestDirector) handle404(request net.Conn) {
	bodyBuf := bytes.NewBufferString("No tunnel found.")
	response := http.Response{
		StatusCode:    404,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          ioutil.NopCloser(bodyBuf),
		ContentLength: int64(bodyBuf.Len()),
	}

	if err := response.Write(request); err != nil {
		log.Warnf("Could not write 404 response: %s", err)
	}

	if err := request.Close(); err != nil {
		log.Warnf("Could not close request", err)
	}
}
