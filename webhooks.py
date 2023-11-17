#!/usr/bin/env python3
from enum import IntEnum
import logging
import requests
import json
import pymsteams
import os
import sys
import socket
from email.mime.text import MIMEText
import email.utils 
from subprocess import Popen, PIPE
import smtplib, ssl

username="honeypot"

class WebHookType(IntEnum):
    NONE = 0
    GENERIC = 1
    SLACK = 2
    TEAMS = 3
    DISCORD = 4
    EMAIL_ONLY = 5

class WebHook:
    DEFAULT_HEADERS = {'Content-Type': 'application/json'}

    def __init__(self, url, hooktype=WebHookType.GENERIC, email="", sendmail = False, smarthost = "", mail_port = 25, mail_user = "", mail_pass = "", use_ssl = False):
        self.url = url
        self.hooktype = hooktype
        self.email = email
        self.sendmail = sendmail
        self.smarthost = smarthost
        self.mail_user = mail_user
        self.mail_pass = mail_pass
        self.mail_port = mail_port
        self.use_ssl = use_ssl

    def notify(self, message):
        if message:
            # Why oh why can't python support switch/case??? >:(
            if self.hooktype == WebHookType.GENERIC:
                self.__send_to_generic_webhook(message)
            elif self.hooktype == WebHookType.SLACK:
                self.__send_to_slack(message)
            elif self.hooktype == WebHookType.TEAMS:
                self.__send_to_teams(message)
            elif self.hooktype == WebHookType.DISCORD:
                self.__send_to_discord(message)

            if self.sendmail:
                self.__send_to_email(message)

    def __send_to_email(self, message):
        logging.debug( "[SENDMAIL] {0}".format(message))
        try:
            hn = socket.gethostname()
            msg = MIMEText(message)

            msg["Subject"] = f"[{hn}] Honeypot Triggered!"
            msg["To"] = self.email

            if len(self.mail_user) == 0: 
                self.mail_user = f"{username}@{hn}"

            msg["From"] = self.mail_user
            msg["Sender"] = self.mail_user
            msg["Date"] = email.utils.formatdate(localtime=True)
 
            # use specified server
            if len(self.smarthost):
                if self.use_ssl:
                    context = ssl.create_default_context()
                    with smtplib.SMTP_SSL(self.smarthost, self.mail_port, context = context) as server:
                        if len(self.mail_pass):
                             server.login(self.mail_user, self.mail_pass)
                        server.sendmail(self.mail_user, self.email, msg.as_bytes())
                else:
                    with smtplib.SMTP(self.smarthost, self.mail_port) as server:
                        if len(self.mail_pass):
                             server.login(self.mail_user, self.mail_pass)
                        server.sendmail(self.mail_user, self.email, msg.as_bytes())
            # use MX
            else:
                #p = Popen(["/usr/sbin/sendmail", "-t", "-oi"], stdin=PIPE) # for plain sendmail mta
                p = Popen(["/usr/sbin/sendmail", self.email], stdin=PIPE) # for exim 
                p.communicate(msg.as_bytes())
                if not p.returncode == 0:
                    logging.debug( "Failed to send notification via sendmail. Return code: {0}".format(p.returncode))

        except Exception as e:
            logging.exception(e)

    def __send_to_generic_webhook(self, message):
        logging.debug( "[WEBHOOK] {0}".format(message))

        data = {
            'content': message,
            'username': username
        }

        try:
            response = requests.post( self.url, data=json.dumps(data), headers=WebHook.DEFAULT_HEADERS)
            if not response.ok:
                logging.debug( "Failed to send notification via Generic webhook. Server response: {0}".format(response.text))
        except Exception as e:
            logging.exception(e)

    # See https://api.slack.com/messaging/webhooks for more info
    def __send_to_slack(self, message):
        logging.debug( "[SLACK] {0}".format(message))

        # Remember to set your webhook up at https://my.slack.com/services/new/incoming-webhook/
        data = {
            'text': message,
            'username': 'Port Scan Honeypot',
            'icon_emoji': ':skull_and_crossbones:'
        }

        try:
            response = requests.post( self.url, data=json.dumps(data), headers=WebHook.DEFAULT_HEADERS)
            if not response.ok:
                logging.debug( "Failed to send notification via Slack. Server response: {0}".format(response.text))
        except Exception as e:
            logging.exception(e)

    # See https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook
    def __send_to_teams(self, message):
        logging.debug( "[TEAMS] {0}".format(message))

        try:
            teams = pymsteams.connectorcard(self.url)
            teams.title( "Port scan detected!")
            teams.text(message)
            teams.send()
        except Exception as e:
            logging.exception(e)

    def __send_to_discord(self, message):
        logging.debug( "[DISCORD] {0}".format(message))

        data = {
            'content': message,
            'username': username
        }

        try:
            response = requests.post( self.url, data=json.dumps(data), headers=WebHook.DEFAULT_HEADERS)
            if not response.ok:
                logging.debug( "Failed to send notification via Discord. Server response: {0}".format(response.text))

        except Exception as e:
            logging.exception(e)

