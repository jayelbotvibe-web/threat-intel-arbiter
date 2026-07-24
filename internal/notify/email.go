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

// headerSafe strips characters that could break out of an SMTP header line:
// CR, LF, and other control characters are removed so source-controlled text
// cannot inject additional headers (e.g. Bcc) via header injection.
func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r < 0x20 {
			return -1
		}
		return r
	}, s)
}

func (n *EmailNotifier) Send(alert model.Alert) error {
	if n.Host == "" {
		return fmt.Errorf("email: no SMTP host configured")
	}

	// Build the Subject from structured fields (severity + event id), and run
	// every header value through headerSafe so CR/LF from source-controlled
	// content (e.g. a MISP event title) can never inject additional SMTP
	// headers such as Bcc. Using alert.Explanation raw here was a header
	// injection vector (and its embedded "\n\n" already broke the subject).
	subject := headerSafe(fmt.Sprintf("[Threat Intel Arbiter] %s: %s (confidence: %s)",
		strings.ToUpper(alert.Severity), alert.EventID, alert.Confidence))

	body := fmt.Sprintf("From: %s\r\n", headerSafe(n.From))
	body += fmt.Sprintf("To: %s\r\n", headerSafe(n.From)) // default to self
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
