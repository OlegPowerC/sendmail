### Утилита для посылки небольших писем через различные почтовые серверы
#### В следующей версии появится возможность приложить файлы

#### Параметры коммандной строки:
    
    -user   Имя пользователя для аутентификации на почтовом сервере
    -pass   Пароль для аутетификации на почтовом сервере
    -to     Адрес получателя письма
    -from   Адрес отправителя письма
    -smtp   Адрес SMTP сервера (fqdn или IP)
    -port   Порт SMTP сервера, например -port 25
    -subj   Тема письма
    -msg    Тело письма
    -domain Домен, который используется с командами HELO/EHLO
    -tls    Использовать TLS (если параметр указан) или STARTTLS (если не указан)
    -file   Использовать JSON файл для всех параметров кроме получателя, темы и тела письма

#### Пример параметров командной строки

**sendmail.exe -user user@yandex.ru -from user@yandex.ru -to user@gmail.com -msg "MSG from Yandex" -subj Test -smtp smtp.yandex.ru -port 465 -pass Password123% -tls**

#### Параметры в файле JSON

    mail_from      Адрес отправителя письма
    mail_from_name  Можно указать имя отправителя
    smtpserver      Адрес SMTP сервера (fqdn или IP)
    smtpport        Порт SMTP сервера, например -port 25
    username        Имя пользователя для аутентификации на почтовом сервере
    smtp_password   Пароль для аутетификации на почтовом сервере
    domain          Домен, который используется с командами HELO/EHLO
    tls             true если используется TLS и false если starttls

#### Пример параметров в файле:

    {
        "smtp_params":{
        "mail_from":"user@yandex.ru",
        "mail_from_name":"LArañiaTools",
        "smtpserver":"smtp.yandex.ru",
        "smtpport":465,
        "username": "user@yandex.ru",
        "smtp_password":"Password123%",
        "domain": "yandex.ru",
        "tls": true
        }
    }

#### Пример выполнеия приложения используя файл

**-file tls.json -subj "Test" -msg "Test new MSG" -to user@gmail.com**