# -*- coding: utf-8 -*-
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
kallithea.model.notification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Model for notifications


This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Nov 20, 2011
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import datetime
import email.message
import email.utils
import logging
import smtplib
import time
import traceback

from tg import app_globals, config
from tg import tmpl_context as c
from tg.i18n import ugettext as _

from kallithea.lib import celerylib, webutils
from kallithea.lib.utils2 import asbool
from kallithea.lib.vcs.utils import author_email
from kallithea.model import db


log = logging.getLogger(__name__)


class NotificationModel(object):

    TYPE_CHANGESET_COMMENT = 'cs_comment'
    TYPE_MESSAGE = 'message'
    TYPE_MENTION = 'mention' # not used
    TYPE_REGISTRATION = 'registration'
    TYPE_PULL_REQUEST = 'pull_request'
    TYPE_PULL_REQUEST_COMMENT = 'pull_request_comment'

    def create(self, created_by, body, recipients=None,
               type_=TYPE_MESSAGE, with_email=True,
               email_kwargs=None, repo_name=None):
        """

        Creates notification of given type

        :param created_by: int, str or User instance. User who created this
            notification
        :param body:
        :param recipients: list of int, str or User objects, when None
            is given send to all admins
        :param type_: type of notification
        :param with_email: send email with this notification
        :param email_kwargs: additional dict to pass as args to email template
        """
        email_kwargs = email_kwargs or {}
        if recipients and not getattr(recipients, '__iter__', False):
            raise Exception('recipients must be a list or iterable')

        created_by_obj = db.User.guess_instance(created_by)

        recipients_objs = set()
        if recipients:
            for u in recipients:
                obj = db.User.guess_instance(u)
                if obj is not None:
                    recipients_objs.add(obj)
                else:
                    # TODO: inform user that requested operation couldn't be completed
                    log.error('cannot email unknown user %r', u)
            log.debug('sending notifications %s to %s',
                type_, recipients_objs
            )
        elif recipients is None:
            # empty recipients means to all admins
            recipients_objs = db.User.query().filter(db.User.admin == True).all()
            log.debug('sending notifications %s to admins: %s',
                type_, recipients_objs
            )
        #else: silently skip notification mails?

        if not with_email:
            return

        headers = {}
        headers['X-Kallithea-Notification-Type'] = type_
        if 'threading' in email_kwargs:
            headers['References'] = ' '.join('<%s>' % x for x in email_kwargs['threading'])

        # this is passed into template
        created_on = webutils.fmt_date(datetime.datetime.now())
        html_kwargs = {
                  'body': None if body is None else webutils.render_w_mentions(body, repo_name),
                  'when': created_on,
                  'user': created_by_obj.username,
                  }

        txt_kwargs = {
                  'body': body,
                  'when': created_on,
                  'user': created_by_obj.username,
                  }

        html_kwargs.update(email_kwargs)
        txt_kwargs.update(email_kwargs)
        email_subject = EmailNotificationModel() \
                            .get_email_description(type_, **txt_kwargs)
        email_txt_body = EmailNotificationModel() \
                            .get_email_tmpl(type_, 'txt', **txt_kwargs)
        email_html_body = EmailNotificationModel() \
                            .get_email_tmpl(type_, 'html', **html_kwargs)

        # don't send email to the person who caused the notification, except for
        # notifications about new pull requests where the author is explicitly
        # added.
        rec_mails = set(obj.email for obj in recipients_objs)
        if type_ == NotificationModel.TYPE_PULL_REQUEST:
            rec_mails.add(created_by_obj.email)
        else:
            rec_mails.discard(created_by_obj.email)

        # send email with notification to participants
        for rec_mail in sorted(rec_mails):
            send_email([rec_mail], email_subject, email_txt_body,
                     email_html_body, headers,
                     from_name=created_by_obj.full_name_or_username)


class EmailNotificationModel(object):

    TYPE_CHANGESET_COMMENT = NotificationModel.TYPE_CHANGESET_COMMENT
    TYPE_MESSAGE = NotificationModel.TYPE_MESSAGE # only used for testing
    # NotificationModel.TYPE_MENTION is not used
    TYPE_PASSWORD_RESET = 'password_link'
    TYPE_REGISTRATION = NotificationModel.TYPE_REGISTRATION
    TYPE_PULL_REQUEST = NotificationModel.TYPE_PULL_REQUEST
    TYPE_PULL_REQUEST_COMMENT = NotificationModel.TYPE_PULL_REQUEST_COMMENT
    TYPE_DEFAULT = 'default'

    def __init__(self):
        super(EmailNotificationModel, self).__init__()
        self._tmpl_lookup = app_globals.mako_lookup
        self.email_types = {
            self.TYPE_CHANGESET_COMMENT: 'changeset_comment',
            self.TYPE_PASSWORD_RESET: 'password_reset',
            self.TYPE_REGISTRATION: 'registration',
            self.TYPE_DEFAULT: 'default',
            self.TYPE_PULL_REQUEST: 'pull_request',
            self.TYPE_PULL_REQUEST_COMMENT: 'pull_request_comment',
        }
        self._subj_map = {
            self.TYPE_CHANGESET_COMMENT: _('[Comment] %(repo_name)s changeset %(short_id)s "%(message_short)s" on %(branch)s by %(cs_author_username)s'),
            self.TYPE_MESSAGE: 'Test Message',
            # self.TYPE_PASSWORD_RESET
            self.TYPE_REGISTRATION: _('New user %(new_username)s registered'),
            # self.TYPE_DEFAULT
            self.TYPE_PULL_REQUEST: _('[Review] %(repo_name)s PR %(pr_nice_id)s "%(pr_title_short)s" from %(pr_source_branch)s by %(pr_owner_username)s'),
            self.TYPE_PULL_REQUEST_COMMENT: _('[Comment] %(repo_name)s PR %(pr_nice_id)s "%(pr_title_short)s" from %(pr_source_branch)s by %(pr_owner_username)s'),
        }

    def get_email_description(self, type_, **kwargs):
        """
        return subject for email based on given type
        """
        tmpl = self._subj_map[type_]
        try:
            subj = tmpl % kwargs
        except KeyError as e:
            log.error('error generating email subject for %r from %s: %s', type_, ', '.join(self._subj_map), e)
            raise
        # gmail doesn't do proper threading but will ignore leading square
        # bracket content ... so that is where we put status info
        bracket_tags = []
        status_change = kwargs.get('status_change')
        if status_change:
            bracket_tags.append(status_change)
        if kwargs.get('closing_pr'):
            bracket_tags.append(_('Closing'))
        if bracket_tags:
            if subj.startswith('['):
                subj = '[' + ', '.join(bracket_tags) + ': ' + subj[1:]
            else:
                subj = '[' + ', '.join(bracket_tags) + '] ' + subj
        return subj

    def get_email_tmpl(self, type_, content_type, **kwargs):
        """
        return generated template for email based on given type
        """
        base = 'email/' + self.email_types.get(type_, self.email_types[self.TYPE_DEFAULT]) + '.' + content_type
        email_template = self._tmpl_lookup.get_template(base)
        # translator and helpers inject
        _kwargs = {'_': _,
                   'webutils': webutils,
                   'c': c}
        _kwargs.update(kwargs)
        if content_type == 'html':
            _kwargs.update({
                "color_text": "#202020",
                "color_emph": "#395fa0",
                "color_link": "#395fa0",
                "color_border": "#ddd",
                "color_background_grey": "#f9f9f9",
                "color_button": "#395fa0",
                "monospace_style": "font-family:Lucida Console,Consolas,Monaco,Inconsolata,Liberation Mono,monospace",
                "sans_style": "font-family:Helvetica,Arial,sans-serif",
                })
            _kwargs.update({
                "default_style": "%(sans_style)s;font-weight:200;font-size:14px;line-height:17px;color:%(color_text)s" % _kwargs,
                "comment_style": "%(monospace_style)s;white-space:pre-wrap" % _kwargs,
                "data_style": "border:%(color_border)s 1px solid;background:%(color_background_grey)s" % _kwargs,
                "emph_style": "font-weight:600;color:%(color_emph)s" % _kwargs,
                "link_style": "color:%(color_link)s;text-decoration:none" % _kwargs,
                "link_text_style": "color:%(color_text)s;text-decoration:none;border:%(color_border)s 1px solid;background:%(color_background_grey)s" % _kwargs,
                })

        log.debug('rendering tmpl %s with kwargs %s', base, _kwargs)
        return email_template.render_unicode(**_kwargs)


@celerylib.task
def send_email(recipients, subject, body='', html_body='', headers=None, from_name=None):
    """
    Sends an email with defined parameters from the .ini files.

    :param recipients: list of recipients, if this is None, the defined email
        address from field 'email_to' and all admins is used instead
    :param subject: subject of the mail
    :param body: plain text body of the mail
    :param html_body: html version of body
    :param headers: dictionary of prepopulated e-mail headers
    :param from_name: full name to be used as sender of this mail - often a
    .full_name_or_username value
    """
    assert isinstance(recipients, list), recipients
    if headers is None:
        headers = {}
    else:
        # do not modify the original headers object passed by the caller
        headers = headers.copy()

    email_config = config
    email_prefix = email_config.get('email_prefix', '')
    if email_prefix:
        subject = "%s %s" % (email_prefix, subject)

    if not recipients:
        # if recipients are not defined we send to email_config + all admins
        recipients = [u.email for u in db.User.query()
                      .filter(db.User.admin == True).all()]
        if email_config.get('email_to') is not None:
            recipients += email_config.get('email_to').split(',')

        # If there are still no recipients, there are no admins and no address
        # configured in email_to, so return.
        if not recipients:
            log.error("No recipients specified and no fallback available.")
            return

        log.warning("No recipients specified for '%s' - sending to admins %s", subject, ' '.join(recipients))

    # SMTP sender
    app_email_from = email_config.get('app_email_from', 'Kallithea')
    # 'From' header
    if from_name is not None:
        # set From header based on from_name but with a generic e-mail address
        # In case app_email_from is in "Some Name <e-mail>" format, we first
        # extract the e-mail address.
        envelope_addr = author_email(app_email_from)
        headers['From'] = '"%s" <%s>' % (
            email.utils.quote('%s (no-reply)' % from_name),
            envelope_addr)

    smtp_server = email_config.get('smtp_server')
    smtp_port = email_config.get('smtp_port')
    smtp_use_tls = asbool(email_config.get('smtp_use_tls'))
    smtp_use_ssl = asbool(email_config.get('smtp_use_ssl'))
    smtp_auth = email_config.get('smtp_auth')  # undocumented - overrule automatic choice of auth mechanism
    smtp_username = email_config.get('smtp_username')
    smtp_password = email_config.get('smtp_password')

    logmsg = ("Mail details:\n"
              "recipients: %s\n"
              "headers: %s\n"
              "subject: %s\n"
              "body:\n%s\n"
              "html:\n%s\n"
              % (' '.join(recipients), headers, subject, body, html_body))

    if smtp_server:
        log.debug("Sending e-mail. " + logmsg)
    else:
        log.error("SMTP mail server not configured - cannot send e-mail.")
        log.warning(logmsg)
        return

    msg = email.message.EmailMessage()
    msg['Subject'] = subject
    msg['From'] = app_email_from  # fallback - might be overridden by a header
    msg['To'] = ', '.join(recipients)
    msg['Date'] = email.utils.formatdate(time.time())

    for key, value in headers.items():
        del msg[key]  # Delete key first to make sure add_header will replace header (if any), no matter the casing
        msg.add_header(key, value)

    msg.set_content(body)
    msg.add_alternative(html_body, subtype='html')

    try:
        if smtp_use_ssl:
            smtp_serv = smtplib.SMTP_SSL(smtp_server, smtp_port)
        else:
            smtp_serv = smtplib.SMTP(smtp_server, smtp_port)

        if smtp_use_tls:
            smtp_serv.starttls()

        if smtp_auth:
            smtp_serv.ehlo()  # populate esmtp_features
            smtp_serv.esmtp_features["auth"] = smtp_auth

        if smtp_username and smtp_password is not None:
            smtp_serv.login(smtp_username, smtp_password)

        smtp_serv.sendmail(app_email_from, recipients, msg.as_string())
        smtp_serv.quit()

        log.info('Mail was sent to: %s' % recipients)
    except:
        log.error('Mail sending failed')
        log.error(traceback.format_exc())
