from __future__ import print_function
from __future__ import unicode_literals

import re

from exchangelib import DELEGATE, IMPERSONATION, Account, Credentials, ServiceAccount, \
    EWSDateTime, EWSTimeZone, Configuration, NTLM, CalendarItem, Message, \
    Mailbox, Attendee, Q, ExtendedProperty, FileAttachment, ItemAttachment, \
    HTMLBody, Build, Version

from urlparse import urlparse
import uuid

import requests
import sys
import json
import time
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

api = TheHiveApi('[thehiveurl]', '[thehiveuser]', '[thehivepassword]', {'http': '', 'https': ''})

creds = Credentials(
    username='DOMAIN\[user]',
    password='[password]')

config = Configuration(server='mail.example.com', credentials=creds)

account = Account(
    primary_smtp_address='[smtpaddress]',
    credentials=creds,
    autodiscover=False,
    config=config,
    access_type=DELEGATE)

to_be_processed_mail_folder = account.root.get_folder_by_name('to_be_processed')
processed_mail_folder = account.root.get_folder_by_name('processed')

num_emails_to_process = to_be_processed_mail_folder.total_count
counter = 0

# Scrape through all emails in folder
print("---------------------Scraping through to_be_processed folder-----------------")
for item in to_be_processed_mail_folder.all().order_by('-datetime_received'):
    malicious_url_desanitized = ''
    malicious_domain = ''
    file_md5 = ''
    counter += 1

    match = re.search('<b>Date:<\/b>[^<]*', item.body)
    date_received = match.group(0).replace("<b>Date:</b>", '').strip()

    match = re.search('<b>From:<\/b>[^<]*', item.body)
    email_from = match.group(0).replace("<b>From:</b>", '').strip()

    match = re.search('<b>To:<\/b>[^<]*', item.body)
    email_to = match.group(0).replace("<b>To:</b>", '')
    email_to = email_to.replace("&lt;", '').split("&gt;")

    match = re.search('<b>CC:<\/b>[^<]*', item.body)
    email_cc = match.group(0).replace("<b>CC:</b>", '')
    email_cc = email_cc.replace("&lt;", '').split("&gt;")

    match = re.search('<b>Subject:<\/b>[^<]*', item.body)
    email_subject = match.group(0).replace("<b>Subject:</b>", '').strip()

    match = re.search('<b>Detected:<\/b>[^<]*', item.body)
    detection = match.group(0).replace("<b>Detected:</b>", '').strip()

    match = re.search('<b>URL/Attachment:<\/b>[^<]*', item.body)
    url_attachment = match.group(0).replace("<b>URL/Attachment:</b>", '').strip()

    if "hxxp" in url_attachment or "hxxps" in url_attachment:
        replace = ('hxxp', 'http'), ('hxxps', 'https'), ('_', '.')
        malicious_url_desanitized = reduce(lambda a, kv: a.replace(*kv), replace, url_attachment)
        parsed_uri = urlparse(malicious_url_desanitized)
        malicious_domain = '{uri.netloc}'.format(uri=parsed_uri)
    else:
        match = re.search('<b>MD5:<\/b>[^<]*', item.body)
        file_md5 = match.group(0).replace("<b>MD5:</b>", '')

    print(
        "---------------------Scraping through {0} of {1} emails in to_be_processed folder-----------------".format(
            counter, num_emails_to_process))
    print("Date Received: " + date_received)
    print("From: " + email_from)
    print("Subject: " + email_subject)
    print("Detected: " + detection)
    if file_md5 != '':
        print("Malicious File: " + url_attachment)
        print("MD5: " + file_md5)
    else:
        print("Malicious URL: " + malicious_url_desanitized)


    description = ''
    description += "**Date Received**: " + date_received + "\n\n"
    description += "**From**: " + email_from + "\n\n"
    description += "**To**: "
    for email in email_to:
        if email != '':
            description += email.strip() + ", "
    description += "\n\n"
    description += "**CC**: "
    for email in email_cc:
        email = email.strip()
        if email != '':
            description += email.strip() + ", "
    description += "\n\n"
    description += "**Subject**: " + email_subject + "\n\n"
    description += "**Detected**: " + detection + "\n\n"
    if file_md5 != '':
        description += "**Malicious File**: " + url_attachment + "\n\n"
        description += "**MD5**: " + file_md5 + "\n\n"
    else:
        description += "**Malicious URL**: " + url_attachment + "\n\n"

    artifacts = []

    if malicious_url_desanitized != '':
        artifacts.extend([
            AlertArtifact(dataType='url', data=malicious_url_desanitized),
            AlertArtifact(dataType='domain', data=malicious_domain),
            AlertArtifact(dataType='mail_subject', data=email_subject)
        ])
    elif file_md5 != '':
        artifacts.extend([
            AlertArtifact(dataType='filename', data=url_attachment),
            AlertArtifact(dataType='hash', data=file_md5)
        ])
    else:
        print("Error!")
        break

    # Prepare the sample Alert
    sourceRef = "email_" + str(uuid.uuid4())[:6]
    alert = Alert(title='Malicious Email Notification',
                      tlp=1,
                      tags=['Mal_Email'],
                      severity=1,
                      description=description,
                      type='email_alert',
                      source='email',
                      sourceRef=sourceRef,
                      artifacts=artifacts)


    # Create the Alert
    print('Create Alert')
    print('-----------------------------')
    id = None
    response = api.create_alert(alert)
    if response.status_code == 201:
        print(json.dumps(response.json(), indent=4, sort_keys=True))
        print('')
        id = response.json()['id']
    else:
        print('ko: {}/{}'.format(response.status_code, response.text))

    item.move(processed_mail_folder)


