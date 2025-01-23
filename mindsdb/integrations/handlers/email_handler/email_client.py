import imaplib
import email
import smtplib
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from datetime import datetime, timedelta

import pandas as pd
from mindsdb.integrations.handlers.email_handler.settings import EmailSearchOptions, EmailConnectionDetails
from mindsdb.utilities import log

logger = log.getLogger(__name__)


class EmailClient:
    '''Class for searching emails using IMAP (Internet Messaging Access Protocol) with OAuth support.'''

    _DEFAULT_SINCE_DAYS = 10

    def __init__(
        self,
        connection_data: EmailConnectionDetails
    ):
        self.email = connection_data.email
        self.password = connection_data.password  # Used only for non-OAuth accounts
        self.oauth_token = connection_data.oauth_token  # OAuth token
        self.imap_server = connection_data.imap_server
        self.smtp_server_address = connection_data.smtp_server
        self.smtp_port = connection_data.smtp_port

        # Initialize IMAP and SMTP objects
        self.imap = None
        self.smtp = None

    def _authenticate_imap(self):
        '''Authenticate with the IMAP server using OAuth or traditional credentials.'''
        try:
            logger.info("Connecting to IMAP server...")
            self.imap = imaplib.IMAP4_SSL(self.imap_server)

            if self.oauth_token:
                logger.info("Authenticating with IMAP using OAuth...")
                auth_string = self._generate_oauth2_string()
                self.imap.authenticate('XOAUTH2', lambda x: auth_string)
            else:
                logger.info("Authenticating with IMAP using username and password...")
                self.imap.login(self.email, self.password)

            logger.info("IMAP authentication successful.")
        except Exception as e:
            logger.error(f"Failed to authenticate with IMAP server: {e}")
            raise Exception("IMAP authentication failed.") from e

    def _authenticate_smtp(self):
        '''Authenticate with the SMTP server using OAuth or traditional credentials.'''
        try:
            logger.info("Connecting to SMTP server...")
            self.smtp = smtplib.SMTP(self.smtp_server_address, self.smtp_port)
            self.smtp.starttls()

            if self.oauth_token:
                logger.info("Authenticating with SMTP using OAuth...")
                auth_string = self._generate_oauth2_string()
                self.smtp.docmd('AUTH XOAUTH2', auth_string)
            else:
                logger.info("Authenticating with SMTP using username and password...")
                self.smtp.login(self.email, self.password)

            logger.info("SMTP authentication successful.")
        except Exception as e:
            logger.error(f"Failed to authenticate with SMTP server: {e}")
            raise Exception("SMTP authentication failed.") from e

    def _generate_oauth2_string(self) -> str:
        '''Generate an OAuth2 authentication string for IMAP and SMTP.'''
        auth_string = f"user={self.email}\x01auth=Bearer {self.oauth_token}\x01\x01"
        return base64.b64encode(auth_string.encode()).decode()

    def select_mailbox(self, mailbox: str = 'INBOX'):
        '''Logs in & selects a mailbox from IMAP server. Defaults to INBOX.'''
        self._authenticate_imap()

        ok, resp = self.imap.select(mailbox)
        if ok != 'OK':
            raise ValueError(
                f"Unable to select mailbox {mailbox}. Please check the mailbox name: {str(resp)}"
            )

        logger.info(f"Selected mailbox {mailbox}")

    def logout(self):
        '''Closes the connection to the IMAP and SMTP servers.'''
        try:
            if self.imap:
                self.imap.logout()
                logger.info("Logged out of IMAP server.")
        except Exception as e:
            logger.error(f"Exception occurred while logging out of IMAP server: {e}")

        try:
            if self.smtp:
                self.smtp.quit()
                logger.info("Logged out of SMTP server.")
        except Exception as e:
            logger.error(f"Exception occurred while logging out of SMTP server: {e}")

    def send_email(self, to_addr: str, subject: str, body: str):
        '''Send an email using SMTP.'''
        self._authenticate_smtp()

        msg = MIMEMultipart()
        msg['From'] = self.email
        msg['To'] = to_addr
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        self.smtp.send_message(msg)
        logger.info(f"Email sent to {to_addr} with subject: {subject}")

    def search_email(self, options: EmailSearchOptions) -> pd.DataFrame:
        '''Search emails based on the given options and return a DataFrame.'''
        self.select_mailbox(options.mailbox)

        try:
            query_parts = []
            if options.subject is not None:
                query_parts.append(f'(SUBJECT "{options.subject}")')

            if options.to_field is not None:
                query_parts.append(f'(TO "{options.to_field}")')

            if options.from_field is not None:
                query_parts.append(f'(FROM "{options.from_field}")')

            if options.since_date is not None:
                since_date_str = options.since_date.strftime('%d-%b-%Y')
            else:
                since_date = datetime.today() - timedelta(days=EmailClient._DEFAULT_SINCE_DAYS)
                since_date_str = since_date.strftime('%d-%b-%Y')
            query_parts.append(f'(SINCE "{since_date_str}")')

            if options.until_date is not None:
                until_date_str = options.until_date.strftime('%d-%b-%Y')
                query_parts.append(f'(BEFORE "{until_date_str}")')

            if options.since_email_id is not None:
                query_parts.append(f'(UID {options.since_email_id}:*)')

            query = ' '.join(query_parts)
            ret = []
            _, items = self.imap.uid('search', None, query)
            items = items[0].split()
            for emailid in items:
                _, data = self.imap.uid('fetch', emailid, '(RFC822)')
                email_message = email.message_from_bytes(data[0][1])

                email_line = {
                    'id': emailid.decode(),
                    'to_field': email_message.get('To'),
                    'from_field': email_message.get('From'),
                    'subject': email_message.get('Subject'),
                    'date': email_message.get('Date')
                }

                # Extract the email body
                plain_payload = None
                html_payload = None
                content_type = 'html'
                for part in email_message.walk():
                    subtype = part.get_content_subtype()
                    if subtype == 'plain':
                        plain_payload = part.get_payload(decode=True)
                        content_type = 'plain'
                        break
                    if subtype == 'html':
                        html_payload = part.get_payload(decode=True)
                body = plain_payload or html_payload
                if body is None:
                    continue
                email_line['body'] = body.decode('utf-8', errors='ignore')
                email_line['body_content_type'] = content_type
                ret.append(email_line)
        except Exception as e:
            raise Exception('Error searching email') from e

        return pd.DataFrame(ret)
