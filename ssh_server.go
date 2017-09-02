package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	sshListenPort    = "2222"
	sshServerKeyPath = "./tunneled_id_rsa"
	userDataPath     = "./users.json"
)

type SSHServer struct {
	config  *ssh.ServerConfig
	port    string
	tunnels map[string]*Tunnel
	users   map[string]*User
	sync.RWMutex
}

func (server *SSHServer) key() ssh.Signer {
	if _, err := os.Stat(sshServerKeyPath); os.IsNotExist(err) {
		log.Info("SSH server key pair does not exist, creating...")

		err := exec.Command("ssh-keygen", "-f", sshServerKeyPath, "-t", "rsa", "-N", "").Run()
		if err != nil {
			log.Panicf("Failed to create SSH key pair for host: %s", err)
		}

		log.Debug("SSH server key pair created")
	}

	keyBytes, err := ioutil.ReadFile(sshServerKeyPath)
	if err != nil {
		log.Panicf("Failed to load host's private SSH key: %s", err)
	}

	key, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		log.Panicf("Failed to parse host's private SSH key: %s", err)
	}

	return key
}

func (server *SSHServer) loadUsers() {
	usersFile, err := os.Open(userDataPath)
	if err != nil {
		log.Panicf("Failed to read users from JSON file: %s", err)
	}

	json.NewDecoder(usersFile).Decode(&server.users)
}

func (server *SSHServer) publicKeyAuthStrategy(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	convertPublicKeyToString := func(key ssh.PublicKey) string {
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	}

	publicKey := convertPublicKeyToString(key)
	serverPublicKey := convertPublicKeyToString(server.key().PublicKey())

	if publicKey == serverPublicKey {
		return &ssh.Permissions{}, nil
	}

	user := server.users[conn.User()]

	if user != nil && publicKey == user.PublicKey {
		log.Infof("Successfully authenticated %s@%s", conn.User(), conn.RemoteAddr())
		user.Login = conn.User()
		return &ssh.Permissions{}, nil
	} else {
		log.Infof("Unauthorized access from %s@%s", conn.User(), conn.RemoteAddr())
		return nil, errors.New("Unauthorized access")
	}
}

func (server *SSHServer) configure() {
	server.loadUsers()

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: server.publicKeyAuthStrategy,
	}

	sshConfig.AddHostKey(server.key())

	server.config = sshConfig
}

func (server *SSHServer) Start() {
	server.configure()

	log.Info("Starting SSH server...")

	listener, err := net.Listen("tcp", "0.0.0.0:"+server.port)
	if err != nil {
		log.Fatalf("Could not start SSH server: %s", err)
	}

	log.Infof("SSH server listening on port %s", server.port)

	defer listener.Close()

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Warnf("Failed to accept incoming SSH connection: %s", err)
		}

		log.Infof("Beginning SSH handshake for %s", tcpConn.RemoteAddr())

		go func() {
			sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, server.config)
			if err != nil {
				log.Infof("Failed to handshake from %s: %s", tcpConn.RemoteAddr(), err)
			} else {
				log.Infof("Connection established for %s@%s (%s)", sshConn.User(), sshConn.RemoteAddr(), sshConn.ClientVersion())

				go server.handleRequests(reqs, sshConn)
				go server.handleChannels(chans, sshConn)
			}
		}()
	}
}

func (server *SSHServer) handleRequests(reqs <-chan *ssh.Request, conn *ssh.ServerConn) {
	for req := range reqs {
		if req.Type == "tcpip-forward" {
			user := server.users[conn.User()]

			if user != nil {
				type tcpIpForwardRequestPayload struct {
					Raddr string
					Rport uint32
				}

				var requestPayload tcpIpForwardRequestPayload

				err := ssh.Unmarshal(req.Payload, &requestPayload)
				if err != nil {
					log.Warnf("Malformed tcpip-forward request %s", err)
					req.Reply(false, nil)
				}

				remoteAddr := requestPayload.Raddr
				remotePort := requestPayload.Rport

				domain := user.Subdomain + ".tunneled.computer"

				log.Infof("Creating tunnel from http://%s:%d to %s for %s", domain, remotePort, remoteAddr, user.Login)

				tun := Tunnel{
					user:       user,
					connection: conn,
					remoteAddr: remoteAddr,
					remotePort: remotePort,
				}

				server.Lock()
				server.tunnels[domain] = &tun
				server.Unlock()

				req.Reply(true, []byte{})
			} else {
				log.Warn("Cannot create tunnel for unidentified user")
				req.Reply(false, nil)
			}
		} else {
			log.Warn("Received non tcpip-forward request: %q WantReply=%q: %q", req.Type, req.WantReply, req.Payload)
			req.Reply(false, nil)
		}
	}
}

func (server *SSHServer) handleChannels(chans <-chan ssh.NewChannel, conn *ssh.ServerConn) {
	for newChannel := range chans {
		go func() {
			channelType := newChannel.ChannelType()

			if channelType != "direct-tcpip" {
				newChannel.Reject(ssh.Prohibited, "direct-tcpip channels only (-NR)")
				log.Infof("Rejected connection for %s@%s: didn't pass -NR flags", conn.User(), conn.RemoteAddr())
				return
			}
		}()
	}
}

func (server *SSHServer) createChannel(tun Tunnel) (ssh.Channel, error) {
	type forwardedTcpIpRequestPayload struct {
		Raddr string
		Rport uint32
		Laddr string
		Lport uint32
	}

	channelPayload := ssh.Marshal(&forwardedTcpIpRequestPayload{
		Raddr: tun.remoteAddr,
		Rport: tun.remotePort,
		Laddr: "localhost",
		Lport: 8000, // TODO: How can we determine this? https://godoc.org/golang.org/x/crypto/ssh#ConnMetadata
	})

	channel, reqs, err := tun.connection.OpenChannel("forwarded-tcpip", channelPayload)
	if err != nil {
		return nil, err
	}

	go ssh.DiscardRequests(reqs)

	return channel, nil
}
