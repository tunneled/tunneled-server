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

type forwardChannelArgs struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

type Server struct {
	Config *ssh.ServerConfig
	Port   string
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
		return err
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

		log.Info(fmt.Sprintf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion()))

		go handleRequests(reqs)
		go handleChannels(chans, sshConn)
	}
}

func handleRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.Type == "tcpip-forward" {
			req.Reply(true, []byte{})
		} else {
			log.Warn("got unexpected request %q WantReply=%q: %q\n", req.Type, req.WantReply, req.Payload)
			req.Reply(false, nil)
		}
	}
}

func handleChannels(chans <-chan ssh.NewChannel, conn *ssh.ServerConn) {
	for newChannel := range chans {
		go handleChannel(newChannel, conn)
	}
}

func handleChannel(newChannel ssh.NewChannel, conn *ssh.ServerConn) {
	channelType := newChannel.ChannelType()

	if channelType != "direct-tcpip" {
		newChannel.Reject(ssh.Prohibited, "direct-tcpip channels only (-NR)")
		log.Info(fmt.Sprintf("Rejecting SSH connection for %s@%s: didn't pass -NR flags", conn.User(), conn.RemoteAddr()))
		return
	}

	args := forwardChannelArgs{}
	err := ssh.Unmarshal(newChannel.ExtraData(), &args)
	if err != nil {
		log.Warning(fmt.Sprintf("Failed to parse channel request data: %s", err))
		newChannel.Reject(ssh.Prohibited, "invalid request data")
		return
	}

	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Panic(fmt.Sprintf("Could not accept channel (%s)", err))
		return
	}

	for req := range requests {
		log.Info(req.Type)
	}

	connection.Close()
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
