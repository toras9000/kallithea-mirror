# -*- coding: utf-8 -*-

import mock

import kallithea
from kallithea.model import db
from kallithea.tests import base


class smtplib_mock(object):

    @classmethod
    def SMTP(cls, server, port):
        return smtplib_mock()

    def ehlo(self):
        pass

    def quit(self):
        pass

    def sendmail(self, sender, dest, msg):
        smtplib_mock.lastsender = sender
        smtplib_mock.lastdest = set(dest)
        smtplib_mock.lastmsg = msg


@mock.patch('kallithea.model.notification.smtplib', smtplib_mock)
class TestMail(base.TestController):

    def test_send_mail_trivial(self):
        mailserver = 'smtp.mailserver.org'
        recipients = ['rcpt1', 'rcpt2']
        envelope_from = 'noreply@mailserver.org'
        subject = 'subject'
        body = 'body'
        html_body = 'html_body'

        config_mock = {
            'smtp_server': mailserver,
            'app_email_from': envelope_from,
        }
        with mock.patch('kallithea.model.notification.config', config_mock):
            kallithea.model.notification.send_email(recipients, subject, body, html_body)

        assert smtplib_mock.lastdest == set(recipients)
        assert smtplib_mock.lastsender == envelope_from
        assert 'From: %s' % envelope_from in smtplib_mock.lastmsg
        assert 'Subject: %s' % subject in smtplib_mock.lastmsg
        assert body in smtplib_mock.lastmsg
        assert html_body in smtplib_mock.lastmsg

    def test_send_mail_no_recipients(self):
        mailserver = 'smtp.mailserver.org'
        recipients = []
        envelope_from = 'noreply@mailserver.org'
        email_to = 'admin@mailserver.org'
        subject = 'subject'
        body = 'body'
        html_body = 'html_body'

        config_mock = {
            'smtp_server': mailserver,
            'app_email_from': envelope_from,
            'email_to': email_to,
        }
        with mock.patch('kallithea.model.notification.config', config_mock):
            kallithea.model.notification.send_email(recipients, subject, body, html_body)

        assert smtplib_mock.lastdest == set([base.TEST_USER_ADMIN_EMAIL, email_to])
        assert smtplib_mock.lastsender == envelope_from
        assert 'From: %s' % envelope_from in smtplib_mock.lastmsg
        assert 'Subject: %s' % subject in smtplib_mock.lastmsg
        assert body in smtplib_mock.lastmsg
        assert html_body in smtplib_mock.lastmsg

    def test_send_mail_no_recipients_multiple_email_to(self):
        mailserver = 'smtp.mailserver.org'
        recipients = []
        envelope_from = 'noreply@mailserver.org'
        email_to = 'admin@mailserver.org,admin2@example.com'
        subject = 'subject'
        body = 'body'
        html_body = 'html_body'

        config_mock = {
            'smtp_server': mailserver,
            'app_email_from': envelope_from,
            'email_to': email_to,
        }
        with mock.patch('kallithea.model.notification.config', config_mock):
            kallithea.model.notification.send_email(recipients, subject, body, html_body)

        assert smtplib_mock.lastdest == set([base.TEST_USER_ADMIN_EMAIL] + email_to.split(','))
        assert smtplib_mock.lastsender == envelope_from
        assert 'From: %s' % envelope_from in smtplib_mock.lastmsg
        assert 'Subject: %s' % subject in smtplib_mock.lastmsg
        assert body in smtplib_mock.lastmsg
        assert html_body in smtplib_mock.lastmsg

    def test_send_mail_no_recipients_no_email_to(self):
        mailserver = 'smtp.mailserver.org'
        recipients = []
        envelope_from = 'noreply@mailserver.org'
        subject = 'subject'
        body = 'body'
        html_body = 'html_body'

        config_mock = {
            'smtp_server': mailserver,
            'app_email_from': envelope_from,
        }
        with mock.patch('kallithea.model.notification.config', config_mock):
            kallithea.model.notification.send_email(recipients, subject, body, html_body)

        assert smtplib_mock.lastdest == set([base.TEST_USER_ADMIN_EMAIL])
        assert smtplib_mock.lastsender == envelope_from
        assert 'From: %s' % envelope_from in smtplib_mock.lastmsg
        assert 'Subject: %s' % subject in smtplib_mock.lastmsg
        assert body in smtplib_mock.lastmsg
        assert html_body in smtplib_mock.lastmsg

    def test_send_mail_with_author(self):
        mailserver = 'smtp.mailserver.org'
        recipients = ['rcpt1', 'rcpt2']
        envelope_from = 'noreply@mailserver.org'
        subject = 'subject'
        body = 'body'
        html_body = 'html_body'
        author = db.User.get_by_username(base.TEST_USER_REGULAR_LOGIN)

        config_mock = {
            'smtp_server': mailserver,
            'app_email_from': envelope_from,
        }
        with mock.patch('kallithea.model.notification.config', config_mock):
            kallithea.model.notification.send_email(recipients, subject, body, html_body, from_name=author.full_name_or_username)

        assert smtplib_mock.lastdest == set(recipients)
        assert smtplib_mock.lastsender == envelope_from
        assert 'From: "Kallithea Admin (no-reply)" <%s>' % envelope_from in smtplib_mock.lastmsg
        assert 'Subject: %s' % subject in smtplib_mock.lastmsg
        assert body in smtplib_mock.lastmsg
        assert html_body in smtplib_mock.lastmsg

    def test_send_mail_with_author_full_mail_from(self):
        mailserver = 'smtp.mailserver.org'
        recipients = ['ræcpt1', 'receptor2 <rcpt2@example.com>', 'tæst@example.com', 'Tæst <test@example.com>']
        envelope_addr = 'noreply@mailserver.org'
        envelope_from = 'Söme Næme <%s>' % envelope_addr
        subject = 'subject'
        body = 'body'
        html_body = 'html_body'
        author = db.User.get_by_username(base.TEST_USER_REGULAR_LOGIN)

        config_mock = {
            'smtp_server': mailserver,
            'app_email_from': envelope_from,
        }
        with mock.patch('kallithea.model.notification.config', config_mock):
            kallithea.model.notification.send_email(recipients, subject, body, html_body, from_name=author.full_name_or_username)

        assert smtplib_mock.lastdest == set(recipients)
        assert smtplib_mock.lastsender == envelope_from
        assert 'From: "Kallithea Admin (no-reply)" <%s>' % envelope_addr in smtplib_mock.lastmsg
        assert 'Subject: %s' % subject in smtplib_mock.lastmsg
        assert body in smtplib_mock.lastmsg
        assert html_body in smtplib_mock.lastmsg

    def test_send_mail_extra_headers(self):
        mailserver = 'smtp.mailserver.org'
        recipients = ['rcpt1', 'rcpt2']
        envelope_from = 'noreply@mailserver.org'
        subject = 'subject'
        body = 'body'
        html_body = 'html_body'
        author = db.User(name='foo', lastname='(fubar) "baz"')
        headers = {'extra': 'yes'}

        config_mock = {
            'smtp_server': mailserver,
            'app_email_from': envelope_from,
        }
        with mock.patch('kallithea.model.notification.config', config_mock):
            kallithea.model.notification.send_email(recipients, subject, body, html_body,
                                                     from_name=author.full_name_or_username, headers=headers)

        assert smtplib_mock.lastdest == set(recipients)
        assert smtplib_mock.lastsender == envelope_from
        assert r'From: "foo (fubar) \"baz\" (no-reply)" <%s>' % envelope_from in smtplib_mock.lastmsg
        assert 'Subject: %s' % subject in smtplib_mock.lastmsg
        assert body in smtplib_mock.lastmsg
        assert html_body in smtplib_mock.lastmsg
        assert 'extra: yes' in smtplib_mock.lastmsg
        # verify that headers dict hasn't mutated by send_email
        assert headers == {'extra': 'yes'}
