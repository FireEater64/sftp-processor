package sftp

import (
	"errors"
	"io/ioutil"
	"time"

	"github.com/flashmob/go-guerrilla/backends"
	"github.com/flashmob/go-guerrilla/mail"
	"github.com/flashmob/go-guerrilla/response"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type sftpConfig struct {
	Username string `json:"sftp_username,omitempty"`
	Password string `json:"sftp_password,omitempty"`
	KeyFile  string `json:"sftp_keyfile,omitempty"`
	KeyPass  string `json:"sftp_keypass,omitempty"`
	Hostname string `json:"sftp_hostname,omitempty"`
	Path     string `json:"sftp_path,omitempty"`
}

// Publisher wraps an SSH connection, and provides methods for saving
// email messages using SFTP
type Publisher struct {
	hostname   string
	sshConfig  *ssh.ClientConfig
	sshClient  *ssh.Client
	sftpClient *sftp.Client
	path       string
}

// New returns a new SftpPublisher, which uses the given ssh.Client
func New(hostname string, sshConfig *ssh.ClientConfig, path string) (*Publisher, error) {
	toReturn := &Publisher{hostname: hostname, sshConfig: sshConfig, path: path}
	err := toReturn.Connect()
	return toReturn, err
}

// Connect establishes a connection using the given credentials
func (p *Publisher) Connect() error {

	var err error
	p.sshClient, err = p.getSSHClient()

	if err != nil {
		return err
	}

	p.sftpClient, err = p.getSFTPClient()

	if err != nil {
		return err
	}

	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()

		for {
			<-t.C
			p.doHealthCheck()
		}
	}()

	return nil
}

// SaveMessage transfers the given message to the configured SFTP share, then
// writes a '.done' file to signify the end of a successful transfer
func (p *Publisher) SaveMessage(emailHash string, data []byte) error {

	// Create email file
	dataFileName := p.sftpClient.Join(p.path, emailHash+".eml")
	dataFile, err := p.sftpClient.Create(dataFileName)

	if err != nil {
		return err
	}

	// Write to the file
	bytesWritten, err := dataFile.Write(data)
	if err != nil {
		return err
	}

	if bytesWritten != len(data) {
		return errors.New("Corrupt upload")
	}

	err = dataFile.Close()
	if err != nil {
		return nil
	}

	// Write the .done file
	doneFileName := dataFileName + ".done"
	doneFile, err := p.sftpClient.Create(doneFileName)
	if err != nil {
		return err
	}

	err = doneFile.Close()
	if err != nil {
		return err
	}

	return nil
}

// Close the underlying clients, and exit gracefully
func (p *Publisher) Close() error {
	if p.sshClient != nil {
		err := p.sshClient.Close()
		if err != nil {
			return err
		}
	}

	p.sshClient = nil
	return nil
}

func (p *Publisher) doHealthCheck() error {
	backends.Log().Debugln("Sending keepalive")

	// Check SSH connection health
	_, _, err := p.sshClient.Conn.SendRequest("keepalive@golang.org", true, nil)
	if err != nil {
		backends.Log().Warnf("Disconnected from server: %s. Attempting to reconnect", err.Error())
		p.sshClient, err = p.getSSHClient()
		if err != nil {
			backends.Log().Fatalf("Error whilst attempting to reconnect to server: %s", err.Error())
			return err
		}
	}

	// Check SFTP client health
	_, err = p.sftpClient.Getwd()
	if err != nil {
		backends.Log().Warnf("SFTP client broken: %s. Attempting to reconnect", err.Error())
		p.sftpClient, err = p.getSFTPClient()
		if err != nil {
			backends.Log().Fatalf("Error whilst attempting to re-establish SFTP client: %s", err.Error())
			return err
		}
	}

	return nil
}

func (p *Publisher) getSSHClient() (*ssh.Client, error) {
	return ssh.Dial("tcp", p.hostname, p.sshConfig)
}

func (p *Publisher) getSFTPClient() (*sftp.Client, error) {
	return sftp.NewClient(p.sshClient)
}

func parsePrivateKeyIfExists(keyFile string, keyPass string) (ssh.Signer, error) {
	// Check for/parse private key
	if keyFile != "" {
		fileContents, err := ioutil.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		privateKey, err := ssh.ParsePrivateKeyWithPassphrase(fileContents, []byte(keyPass))
		if err != nil {
			return nil, err
		}

		return privateKey, err
	}

	return nil, nil
}

// SFTPProcessor is the main decorator, to be registered with the Guerilla daemon
var SFTPProcessor = func() backends.Decorator {
	var publisher *Publisher

	// Config to be populated by initFunc
	initializer := backends.InitializeWith(func(backendConfig backends.BackendConfig) error {

		// Parse config
		configType := backends.BaseConfig(&sftpConfig{})

		parsedConfig, err := backends.Svc.ExtractConfig(backendConfig, configType)

		if err != nil {
			backends.Log().Fatalln(err)
			return err
		}

		config := parsedConfig.(*sftpConfig)

		// Establish an SSH connection
		sshConfig := &ssh.ClientConfig{
			User: config.Username,

			Auth: []ssh.AuthMethod{
				ssh.Password(config.Password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		// Parse SSH keys
		signers, err := parsePrivateKeyIfExists(config.KeyFile, config.KeyPass)
		if err != nil {
			return err
		}
		if signers != nil {
			sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(signers))
		}

		if publisher == nil {
			publisher, err = New(config.Hostname, sshConfig, config.Path)
			if err != nil {
				return err
			}
		}

		if err != nil {
			print(err)
			return err
		}

		return nil
	})

	// Register initializer
	backends.Svc.AddInitializer(initializer)

	// Cleanly shutdown SFTP connection when stopping
	backends.Svc.AddShutdowner(backends.ShutdownWith(func() error {
		return publisher.Close()
	}))

	return func(p backends.Processor) backends.Processor {
		return backends.ProcessWith(
			func(e *mail.Envelope, task backends.SelectTask) (backends.Result, error) {
				if task == backends.TaskSaveMail {

					// Compute filename from email hash
					if len(e.Hashes) == 0 {
						backends.Log().Error("SFTP needs a Hash() process before it")
						result := backends.NewResult(response.Canned.FailBackendTransaction)
						return result, backends.StorageError
					}

					e.QueuedId = e.Hashes[0]
					hash := e.Hashes[0]

					err := publisher.SaveMessage(hash, e.Data.Bytes())

					if err != nil {
						backends.Log().WithError(err).Error("Could not upload file")
						return backends.NewResult(response.Canned.ErrorRelayDenied), backends.StorageError
					}

					backends.Log().Info("%s delivered", hash)

					return p.Process(e, task)
				}
				return p.Process(e, task)
			},
		)
	}
}
