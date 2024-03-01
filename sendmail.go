package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

type SMTPSettings struct {
	MailFrom     string `xml:"mail_from" json:"mail_from"`
	MailFromName string `xml:"mail_from_name" json:"mail_from_name"`
	SMTPserver   string `xml:"smtpserver" json:"smtpserver"`
	Username     string `xml:"username" json:"username"`
	SMTPPort     uint   `xml:"smtpport" json:"smtpport"`
	Domain       string `xml:"domain" json:"domain"`
	SMTPPassword string `xml:"smtp_password" json:"smtp_password"`
	TLSUsage     bool   `xml:"tls" json:"tls"`
}

type ESettings struct {
	SMTPParams SMTPSettings `xml:"smtp_params" json:"smtp_params"`
}

type GlobalData struct {
	EntireSettings ESettings
	UmapMutex      sync.Mutex
	LogToParam     byte
}

type loginAuth struct {
	username, password string
}

func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			return nil, errors.New("Unkown fromServer")
		}
	}
	return nil, nil
}

func SendMail(MailAddr string, MSGSubject string, Message string, settings SMTPSettings, Debuglevel int) error {
	var c *smtp.Client
	var err error

	tlsusage := settings.TLSUsage

	from := mail.Address{settings.MailFromName, settings.MailFrom}
	to := mail.Address{"", MailAddr}
	subj := MSGSubject
	body := Message

	// Setup headers
	headers := make(map[string]string)
	headers["From"] = from.String()
	headers["To"] = to.String()
	headers["Subject"] = subj
	headers["Content-Type"] = "text/plain; charset=utf-8"

	// Setup message
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body
	servername := fmt.Sprintf("%s:%d", settings.SMTPserver, settings.SMTPPort)
	host := settings.SMTPserver
	if Debuglevel > 0 {
		fmt.Println("SMTP server:", servername)
	}

	authlogin := LoginAuth(settings.Username, settings.SMTPPassword)
	if Debuglevel > 0 {
		fmt.Println("Login Auth:", authlogin)
	}

	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	if tlsusage {
		conn, err := tls.Dial("tcp", servername, tlsconfig)
		if err != nil {
			log.Panic(err)
		}
		c, err = smtp.NewClient(conn, host)
		if err != nil {
			log.Panic(err)
		}
	} else {
		c, err = smtp.Dial(servername)
		if err != nil {
			return err
		}

		starttlserr := c.StartTLS(tlsconfig)
		if starttlserr != nil {
			return starttlserr
		}
	}

	autherr := c.Auth(authlogin)
	if autherr != nil {
		return autherr
	}

	fromerr := c.Mail(from.Address)
	if fromerr != nil {
		return fromerr
	}

	toerr := c.Rcpt(to.Address)
	if toerr != nil {
		return toerr
	}

	w, dataerr := c.Data()
	if dataerr != nil {
		return dataerr
	}

	_, werr := w.Write([]byte(message))
	if werr != nil {
		return werr
	}

	cerr := w.Close()
	if cerr != nil {
		return cerr
	}

	c.Quit()
	return nil
}

var GlobalDataSt GlobalData

func main() {
	errcounter := 0
	Mailto := flag.String("to", "", "Получатель тестового сообщения")
	From := flag.String("from", "", "Отправитель тестового сообщения")
	SMTPUser := flag.String("user", "", "Имя пользователя")
	SMTPPasswor := flag.String("pass", "", "Пароль")
	Domain := flag.String("domain", "test.ru", "Домен для HELLO/EHLO - по умолчанию test.ru")
	Subject := flag.String("subj", "", "Тема письма")
	Message := flag.String("msg", "", "Тело письма")
	SMTPServer := flag.String("smtp", "", "Адрес smtp сервера")
	Usefile := flag.String("file", "", "использовать файл - указать имя файла JSON")
	Port := flag.Int("port", 25, "Порт smtp сервера")
	TLSusage := flag.Bool("tls", false, "Использовать TLS, по умолчаию выключено и используется STARTTLS")
	DebugLevel := flag.Int("debug", 0, "Уровень отладки, по умолчанию ноль")
	flag.Parse()

	if len(*Mailto) < 5 {
		fmt.Println("Пожалуйста укажите получателя письма (параметр -to пример: -to test@example.com ")
		errcounter++
	}

	if len(*Subject) == 0 {
		fmt.Println("Пожалуйста укажите тему письма  (параметр -subj пример: -subj Message ")
		errcounter++
	}

	if len(*Message) < 5 {
		fmt.Println("Пожалуйста укажите тело мисьма (параметр -msg пример: -msg \"Test message\" ")
		errcounter++
	}

	if errcounter > 0 {
		os.Exit(-1)
	}
	if len(*Usefile) > 3 {
		exfullpath, err := os.Executable()
		if err != nil {
			panic(err)
		}
		exPath := filepath.Dir(exfullpath)
		PathSeparator := "/"
		if runtime.GOOS == "windows" {
			PathSeparator = "\\"
		}

		SettingsFileName := *Usefile

		SettingsFileFullName := fmt.Sprintf("%s%s%s", exPath, PathSeparator, SettingsFileName)

		SettingsRead, SettingsReadErr := ioutil.ReadFile(SettingsFileFullName)
		if SettingsReadErr != nil {
			panic(SettingsReadErr)
		}

		JsonUMErr := json.Unmarshal(SettingsRead, &GlobalDataSt.EntireSettings)
		if JsonUMErr != nil {
			panic(JsonUMErr)
		}
	} else {
		if len(*From) < 5 {
			fmt.Println("Пожалуйста укажите отправителя письма (параметр -from пример: -to robot@example.com ")
			os.Exit(-1)
		}

		GlobalDataSt.EntireSettings.SMTPParams.SMTPPort = uint(*Port)
		GlobalDataSt.EntireSettings.SMTPParams.SMTPserver = *SMTPServer
		GlobalDataSt.EntireSettings.SMTPParams.Username = *SMTPUser
		GlobalDataSt.EntireSettings.SMTPParams.SMTPPassword = *SMTPPasswor
		GlobalDataSt.EntireSettings.SMTPParams.MailFrom = *From
		GlobalDataSt.EntireSettings.SMTPParams.Domain = *Domain
		GlobalDataSt.EntireSettings.SMTPParams.TLSUsage = *TLSusage
	}

	if len(GlobalDataSt.EntireSettings.SMTPParams.Username) == 0 {
		GlobalDataSt.EntireSettings.SMTPParams.Username = GlobalDataSt.EntireSettings.SMTPParams.MailFrom
	}

	SMTPerr := SendMail(*Mailto, *Subject, *Message, GlobalDataSt.EntireSettings.SMTPParams, *DebugLevel)
	if SMTPerr != nil {
		fmt.Println(SMTPerr)
	} else {
		fmt.Println("Письмо отправлено")
	}
}
