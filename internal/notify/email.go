package notify

import (
	"fmt"
	"net/smtp"
	"os"
	"strings"

	"github.com/jayelbotvibe-web/threat-intel-arbiter/internal/model"
)

// EmailNotifier sends alerts via SMTP.
type EmailNotifier struct {
	Host     string
	Port     string
	From     string
	Password string
}

// NewEmailNotifier creates an email notifier from env or config.
func NewEmailNotifier(host, port, from, password string) *EmailNotifier {
	if host == "" {
		host = os.Getenv("SMTP_HOST")
	}
	if port == "" {
		port = os.Getenv("SMTP_PORT")
		if port == "" {
			port = "587"
		}
	}
	if from == "" {
		from = os.Getenv("SMTP_FROM")
		if from == "" {
			from = "arbiter@localhost"
		}
	}
	if password == "" {
		password = os.Getenv("SMTP_PASSWORD")
	}
	return &EmailNotifier{
		Host:     host,
		Port:     port,
		From:     from,
		Password: password,
	}
}

func (n *EmailNotifier) Name() string { return "email" }

func (n *EmailNotifier) Send(alert model.Alert) error {
	if n.Host == "" {
		return fmt.Errorf("email: no SMTP host configured")
	}

	// Build plain text email
	subject := fmt.Sprintf("[Threat Intel Arbiter] %s: %s",
		strings.ToUpper(alert.Severity), alert.Explanation[:min(len(alert.Explanation), 80)])

	body := fmt.Sprintf("From: %s\r\n", n.From)
	body += fmt.Sprintf("To: %s\r\n", n.From) // default to self; routing.yaml overrides
	body += fmt.Sprintf("Subject: %s\r\n", subject)
	body += "MIME-Version: 1.0\r\n"
	body += "Content-Type: text/plain; charset=\"utf-8\"\r\n"
	body += "\r\n"
	body += alert.Explanation
	body += fmt.Sprintf("\n\nSeverity: %s · Confidence: %s", strings.ToUpper(alert.Severity), alert.Confidence)
	body += fmt.Sprintf("\nAlert ID: %s · Event: %s\n", alert.ID, alert.EventID)

	// Connect and send
	addr := fmt.Sprintf("%s:%s", n.Host, n.Port)
	auth := smtp.PlainAuth("", n.From, n.Password, n.Host)

	err := smtp.SendMail(addr, auth, n.From, []string{n.From}, []byte(body))
	if err != nil {
		return fmt.Errorf("email send: %w", err)
	}
	return nil
}
