package main

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"syscall"
)

const (
	privateHostKeyPath = "./tunneled.master.key"
)

func init() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.InfoLevel)
}

func handleServerConn(keyID string, chans <-chan ssh.NewChannel) {
	fmt.Println(keyID)
}

func createHostKey() ssh.Signer {
	sshKeygenBinary, err := exec.LookPath("ssh-keygen")
	if err != nil {
		panic(err)
	}

	keygenArgs := []string{"ssh-keygen", "-f", privateHostKeyPath, "-t", "rsa", "-N", ""}

	execErr := syscall.Exec(sshKeygenBinary, keygenArgs, os.Environ())
	if execErr != nil {
		log.Error("Failed to create private key for host")
		panic(err)
	}

	log.Info("New private host key generated: %s", privateHostKeyPath)
	return loadPrivateHostKey()
}

func loadPrivateHostKey() ssh.Signer {
	privateHostKeyBytes, err := ioutil.ReadFile(privateHostKeyPath)
	if err != nil {
		panic("Fail to load private key")
	}

	privateHostKey, err := ssh.ParsePrivateKey(privateHostKeyBytes)
	if err != nil {
		panic("Fail to parse private key")
	}

	return privateHostKey
}

func main() {
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fmt.Println(ssh.MarshalAuthorizedKey(key))

			//publicKey, err := models.SearchPublicKeyByContent(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))

			//if err != nil {
			//	log.Error(3, "SearchPublicKeyByContent: %v", err)
			//	return nil, err
			//}
			//return &ssh.Permissions{Extensions: map[string]string{"key-id": com.ToStr(publicKey.ID)}}, nil
			return &ssh.Permissions{Extensions: map[string]string{"key-id": "foo"}}, nil
		},
	}

	var privateHostKey ssh.Signer

	if _, err := os.Stat(privateHostKeyPath); os.IsNotExist(err) {
		log.Info("Host key does not exist, creating")
		privateHostKey = createHostKey()
	} else {
		log.Info("Host key exists")
		privateHostKey = loadPrivateHostKey()
	}

	config.AddHostKey(privateHostKey)

	listener, err := net.Listen("tcp", "0.0.0.0:2222")

	if err != nil {
		panic(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Error("SSH: Error accepting incoming connection: %v", err)
		}

		// Use a separate go routine to establish the handshake to ensure this is non-blocking
		go func() {
			log.Info("SSH: Handshaking for %s", conn.RemoteAddr())
			sConn, chans, reqs, err := ssh.NewServerConn(conn, config)
			if err != nil {
				if err == io.EOF {
					log.Warn("SSH: Handshaking was terminated: %v", err)
				} else {
					log.Error(3, "SSH: Error on handshaking: %v", err)
				}
				return
			}

			log.Info("SSH: Connection from %s (%s)", sConn.RemoteAddr(), sConn.ClientVersion())
			go ssh.DiscardRequests(reqs)
			go handleServerConn(sConn.Permissions.Extensions["key-id"], chans)
		}()
	}
}
