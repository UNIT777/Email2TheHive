# Email2TheHive
Generate TheHive alerts from emails

## Prerequisites
### Mailbox with the following folders
A Mailbox with the following folders is required:
```
processed
to_be_processed
```
### Exchange Service account
An Exchange Service account with Read/Write permissions to the following folders:
```
processed
to_be_processed
```

## Python Packages Required
```
exchangelib==1.9.3
python-magic==0.4.13
thehive4py==1.2.0
requests
```
## Hard Coded configuration items that need to be changed
Specify TheHive URL, username, password:
```
api = TheHiveApi('[thehiveurl]', '[thehiveuser]', '[thehivepassword]', {'http': '', 'https': ''})

```

Specify Exchange service account:
```
creds = Credentials(
    username='DOMAIN\[user]',
    password='[password]')
```

Specify SMTP address
```
primary_smtp_address='[smtpaddress]',
```

## (IF NEEDED) Requests Python Modifications Required for SSL
Set the REQUESTS_CA_BUNDLE environment variable to the path of the certificate file (*.pem) (full certificate chain: primary, intermediate, root) when running the script
Example in a Terminal/Shell:
```
REQUESTS_CA_BUNDLE=~/CAfile.pem ./GenerateAlert.py
```

## Errors
### ASCII encoding error in CRON job
To fix this error specify the following at the top of your crontab
```
PYTHONIOENCODING=utf8
```


## Authors
* **brevillebro** - *Initial Work*

## Roadmap/TODO
* Read required parameters from a config file
* Error checking
* Logging (success/error)
* Code cleanup
