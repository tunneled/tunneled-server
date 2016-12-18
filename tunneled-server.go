package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"

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

//TODO: Find a better name
type forwardRequest struct {
	BindIP   string
	BindPort uint32
}

type Server struct {
	Config *ssh.ServerConfig
	Port   string
}

func main() {
	config := &ssh.ServerConfig{
		PublicKeyCallback: authorizeByPublicKey,
	}

	hostKey := findOrCreateHostKey()
	config.AddHostKey(hostKey)

	server := &Server{
		Config: config,
		Port:   port,
	}

	server.Start()
}

func findOrCreateHostKey() ssh.Signer {
	if _, err := os.Stat(privateHostKeyPath); os.IsNotExist(err) {
		log.Info("SSH: Host key does not exist, creating...")
		createHostKey()
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

func createHostKey() {
	cmd := exec.Command("ssh-keygen", "-f", privateHostKeyPath, "-t", "rsa", "-N", "")

	err := cmd.Run()

	if err != nil {
		log.Panic(fmt.Sprintf("SSH: Failed to create private key for host %s", err))
	}
}

func authorizeByPublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	// TODO: Perform lookup to see if key is known, find associated user.
	//formattedKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))

	return &ssh.Permissions{}, nil
}

func (server *Server) Start() error {
	log.Info("Starting server...")
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)

	if err != nil {
		log.Fatal(fmt.Sprintf("Could not start server: %s", err))
	}

	defer listener.Close()

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Panic(fmt.Sprintf("Failed to accept incoming connection (%s)", err))
		}

		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, server.Config)
		if err != nil {
			log.Panic(fmt.Sprintf("Failed to handshake (%s)", err))
		}

		log.Info(fmt.Sprintf("New SSH connection from %s@%s (%s)", sshConn.User(), sshConn.RemoteAddr(), sshConn.ClientVersion()))

		go handleRequests(reqs, sshConn)
		go handleChannels(chans, sshConn)
	}
}

func handleRequests(reqs <-chan *ssh.Request, conn *ssh.ServerConn) {
	for req := range reqs {
		if req.Type == "tcpip-forward" {

			var forwardReq forwardRequest
			err := ssh.Unmarshal(req.Payload, &forwardReq)
			if err != nil {
				log.Warn(fmt.Sprintf("Malformed request %s", err))
				req.Reply(false, nil)
			}

			log.Info(fmt.Sprintf("%s is requesting port %d to be forwarded to %s", conn.User(), forwardReq.BindPort, conn.RemoteAddr()))

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
