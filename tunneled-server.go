// Notes
// https://github.com/pivotal-cf-experimental/remote-pairing-release/blob/master/src/github.com/pivotal-cf-experimental/ssh-tunnel/server.go#L298
// https://github.com/Sirupsen/logrus
// https://github.com/emulbreh/sshub/blob/c14f516babcc121ae62de2ada5ebffd779e4d6b6/libsshub/hub.go
// ssh -NR 8001:localhost:8000 brooks@localhost -p 2222

package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func init() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
}

const (
	privateHostKeyPath = "./tunneled.master.key"
	port               = "2222"
)

type tunnel struct {
	user            *user
	source          net.Addr
	destinationPort uint32
}

//TODO: Find a better name
type tcpIpForwardPayload struct {
	BindIP   string
	BindPort uint32
}

type tunnelServer struct {
	config  *ssh.ServerConfig
	port    string
	tunnels map[string]*tunnel
	users   map[string]*user
	sync.Mutex
}

type user struct {
	login     string
	publicKey string
	subdomain string
}

var server = &tunnelServer{
	port:    port,
	tunnels: map[string]*tunnel{},
	users:   map[string]*user{},
}

func main() {
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: authorizeByPublicKey,
	}

	hostKey := findOrCreateHostKey()
	sshConfig.AddHostKey(hostKey)

	server.config = sshConfig
	server.hydrateUsers()
	server.Start()
}

func findOrCreateHostKey() ssh.Signer {
	if _, err := os.Stat(privateHostKeyPath); os.IsNotExist(err) {
		log.Info("SSH: Host key does not exist, creating...")

		err := exec.Command("ssh-keygen", "-f", privateHostKeyPath, "-t", "rsa", "-N", "").Run()
		if err != nil {
			log.Panic(fmt.Sprintf("SSH: Failed to create private key for host %s", err))
		}
	}

	hostKeyBytes, err := ioutil.ReadFile(privateHostKeyPath)
	if err != nil {
		log.Panic("SSH: Failed to load host's private key")
	}

	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		log.Panic("SSH: Failed to parse host's private key")
	}

	return hostKey
}

func authorizeByPublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	user := server.users[conn.User()]
	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))

	if user != nil && user.publicKey == publicKey {
		log.Debug(fmt.Sprintf("Successfully authenticated %s@%s", conn.User(), conn.RemoteAddr()))
		return &ssh.Permissions{}, nil
	} else {
		err := errors.New("Unauthorized access")
		log.Debug(fmt.Sprintf("Unauthorized access from %s@%s", conn.User(), conn.RemoteAddr()))
		return nil, err
	}
}

func (server *tunnelServer) hydrateUsers() {
	server.users["bswinnerton"] = &user{
		login:     "brooks",
		subdomain: "bswinnerton.tunneled.computer",
		publicKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCVn/shbTiKA+cfiqtQukE7Tb883fB7mOia7GJzwNBXUe8mB0yMJTmE34L8ZhOv+8+RNMFUAY+YMjFqcRRwhh3NKI3CQQZEU/Ka6YXCwuBrdQipHjwRiZjhyS47rCtnQ+2y1V7CZeCPkIKUZQGa20GdNC8+U6f26WdZVLAQN+pJ6kyIvnNW4AgTLSJsJqgndYqwJ4aPpL/HTC4DM4WpM01/ep/iuvIQcC+vKAUjwomIcD+R3YScQVWQuRQuIoX22lafwkcupyNkYCEp8EK3XvWP5ezv8EeJOI+CfO4z+mKD+gRztKXt53N+eD9Aew3XfzlJCieWNNuzZ0hfxmPDqn7",
	}
}

func (server *tunnelServer) Start() error {
	log.Info("Starting server...")
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)

	if err != nil {
		log.Fatal(fmt.Sprintf("Could not start server: %s", err))
	}

	defer listener.Close()

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Warn(fmt.Sprintf("Failed to accept incoming connection (%s)", err))
		}

		log.Debug(fmt.Sprintf("Beginning SSH handshake for %s", tcpConn.RemoteAddr()))

		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, server.config)
		if err != nil {
			log.Warn(fmt.Sprintf("Failed to handshake from %s: %s", tcpConn.RemoteAddr(), err))
		} else {
			log.Info(fmt.Sprintf("Connection established for %s@%s (%s)", sshConn.User(), sshConn.RemoteAddr(), sshConn.ClientVersion()))

			go handleRequests(reqs, sshConn, server)
			go handleChannels(chans, sshConn)
		}
	}
}

func handleRequests(reqs <-chan *ssh.Request, conn *ssh.ServerConn, server *tunnelServer) {
	for req := range reqs {
		if req.Type == "tcpip-forward" {
			var payload tcpIpForwardPayload
			err := ssh.Unmarshal(req.Payload, &payload)
			if err != nil {
				log.Warn(fmt.Sprintf("Malformed request %s", err))
				req.Reply(false, nil)
			}

			user := server.users[conn.User()]
			port := payload.BindPort
			addr := conn.RemoteAddr()

			log.Info(fmt.Sprintf("Creating tunnel from http://%s:%d to %s  for %s", user.subdomain, port, addr, user.login))

			tun := tunnel{user: user, destinationPort: port, source: addr}

			server.Lock()
			server.tunnels[user.subdomain] = &tun
			server.Unlock()

			// Set up forwards

			req.Reply(true, []byte{})
		} else {
			log.Warn("got unexpected request %q WantReply=%q: %q\n", req.Type, req.WantReply, req.Payload)
			req.Reply(false, nil)
		}
	}
}

func handleChannels(chans <-chan ssh.NewChannel, conn *ssh.ServerConn) {
	for newChannel := range chans {
		go func() {
			channelType := newChannel.ChannelType()

			if channelType != "direct-tcpip" {
				newChannel.Reject(ssh.Prohibited, "direct-tcpip channels only (-NR)")
				log.Info(fmt.Sprintf("Rejecting SSH connection for %s@%s: didn't pass -NR flags", conn.User(), conn.RemoteAddr()))
				return
			}
		}()
	}
}
