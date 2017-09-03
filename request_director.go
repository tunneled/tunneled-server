package main

import (
	"bufio"
	"bytes"
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
		request, err := listener.Accept()
		if err != nil {
			log.Warnf("Could not accept connection: %s", err)
			continue
		}

		var requestBuf bytes.Buffer
		requestReader := io.TeeReader(request, &requestBuf)

		httpRequest, err := http.ReadRequest(bufio.NewReader(requestReader))
		if err != nil {
			log.WithFields(log.Fields{
				"remote_ip": request.RemoteAddr(),
			}).Warnf("Couldn't parse request as HTTP: %s", err)
			continue
		}

		domain := httpRequest.Host

		contextLogger := log.WithFields(log.Fields{
			"remote_ip":          request.RemoteAddr(),
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

		director.sshServer.RLock()
		tun := director.sshServer.tunnels[domain]
		director.sshServer.RUnlock()

		if tun == nil {
			contextLogger.Infof("Couldn't find a tunnel for: http://%s", domain)

			director.Handle404(request)
			continue
		}

		sshChannel, err := director.sshServer.createChannel(*tun)
		if err != nil {
			contextLogger.Warnf("Couldn't create a tunnel for: http://%s", domain)

			director.Handle404(request)
			continue
		}

		go func() {
			_, err := io.Copy(sshChannel, &requestBuf)
			if err != nil {
				contextLogger.Warnf("Couldn't copy request to tunnel: %s", err)
				return
			}

			if err = sshChannel.CloseWrite(); err != nil {
				contextLogger.Warnf("Could not close SSH channel: %s", err)
			}

			_, err = io.Copy(request, sshChannel)
			if err != nil {
				contextLogger.Warnf("Couldn't copy response from tunnel: %s", err)
				return
			}

			contextLogger.Info("Returned response")

			if err = request.Close(); err != nil {
				contextLogger.Warnf("Could not close request: %s", err)
			}
		}()
	}
}

func (director *RequestDirector) Handle404(request net.Conn) {
	bodyBuf := bytes.NewBufferString("No tunnel found.")
	response := http.Response{
		StatusCode:    404,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          ioutil.NopCloser(bodyBuf),
		ContentLength: int64(bodyBuf.Len()),
	}

	if err := response.Write(request); err != nil {
		log.Infof("Could not write 404 response: %s", err)
	}

	if err := request.Close(); err != nil {
		log.Infof("Could not close client connection", err)
	}
}
