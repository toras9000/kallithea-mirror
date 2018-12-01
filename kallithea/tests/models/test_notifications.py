import os
import re

import mock
import routes.util

from kallithea.tests.base import *
from kallithea.lib import helpers as h
from kallithea.model.db import User, Notification, UserNotification
from kallithea.model.user import UserModel
from kallithea.model.meta import Session
from kallithea.model.notification import NotificationModel, EmailNotificationModel

import kallithea.lib.celerylib
import kallithea.lib.celerylib.tasks

from tg.util.webtest import test_context


class TestNotifications(TestController):

    def setup_method(self, method):
        Session.remove()
        u1 = UserModel().create_or_update(username=u'u1',
                                        password=u'qweqwe',
                                        email=u'u1@example.com',
                                        firstname=u'u1', lastname=u'u1')
        Session().commit()
        self.u1 = u1.user_id

        u2 = UserModel().create_or_update(username=u'u2',
                                        password=u'qweqwe',
                                        email=u'u2@example.com',
                                        firstname=u'u2', lastname=u'u3')
        Session().commit()
        self.u2 = u2.user_id

        u3 = UserModel().create_or_update(username=u'u3',
                                        password=u'qweqwe',
                                        email=u'u3@example.com',
                                        firstname=u'u3', lastname=u'u3')
        Session().commit()
        self.u3 = u3.user_id

        self.remove_all_notifications()
        assert [] == Notification.query().all()
        assert [] == UserNotification.query().all()

    def test_create_notification(self):
        with test_context(self.app):
            usrs = [self.u1, self.u2]

            def send_email(recipients, subject, body='', html_body='', headers=None, author=None):
                assert recipients == ['u2@example.com']
                assert subject == 'Test Message'
                assert body == u"hi there"
                assert '>hi there<' in html_body
                assert author.username == 'u1'
            with mock.patch.object(kallithea.lib.celerylib.tasks, 'send_email', send_email):
                notification = NotificationModel().create(created_by=self.u1,
                                                   subject=u'subj', body=u'hi there',
                                                   recipients=usrs)
                Session().commit()
                u1 = User.get(self.u1)
                u2 = User.get(self.u2)
                u3 = User.get(self.u3)
                notifications = Notification.query().all()
                assert len(notifications) == 1

                assert notifications[0].recipients == [u1, u2]
                assert notification.notification_id == notifications[0].notification_id

                unotification = UserNotification.query() \
                    .filter(UserNotification.notification == notification).all()

                assert len(unotification) == len(usrs)
                assert set([x.user_id for x in unotification]) == set(usrs)

    def test_user_notifications(self):
        with test_context(self.app):
            notification1 = NotificationModel().create(created_by=self.u1,
                                                subject=u'subj', body=u'hi there1',
                                                recipients=[self.u3])
            Session().commit()
            notification2 = NotificationModel().create(created_by=self.u1,
                                                subject=u'subj', body=u'hi there2',
                                                recipients=[self.u3])
            Session().commit()
            u3 = Session().query(User).get(self.u3)

            assert sorted([x.notification for x in u3.notifications]) == sorted([notification2, notification1])

    def test_delete_notifications(self):
        with test_context(self.app):
            notification = NotificationModel().create(created_by=self.u1,
                                               subject=u'title', body=u'hi there3',
                                        recipients=[self.u3, self.u1, self.u2])
            Session().commit()
            notifications = Notification.query().all()
            assert notification in notifications

            Notification.delete(notification.notification_id)
            Session().commit()

            notifications = Notification.query().all()
            assert notification not in notifications

            un = UserNotification.query().filter(UserNotification.notification
                                                 == notification).all()
            assert un == []

    def test_delete_association(self):
        with test_context(self.app):
            notification = NotificationModel().create(created_by=self.u1,
                                               subject=u'title', body=u'hi there3',
                                        recipients=[self.u3, self.u1, self.u2])
            Session().commit()

            unotification = UserNotification.query() \
                                .filter(UserNotification.notification ==
                                        notification) \
                                .filter(UserNotification.user_id == self.u3) \
                                .scalar()

            assert unotification.user_id == self.u3

            NotificationModel().delete(self.u3,
                                       notification.notification_id)
            Session().commit()

            u3notification = UserNotification.query() \
                                .filter(UserNotification.notification ==
                                        notification) \
                                .filter(UserNotification.user_id == self.u3) \
                                .scalar()

            assert u3notification == None

            # notification object is still there
            assert Notification.query().all() == [notification]

            # u1 and u2 still have assignments
            u1notification = UserNotification.query() \
                                .filter(UserNotification.notification ==
                                        notification) \
                                .filter(UserNotification.user_id == self.u1) \
                                .scalar()
            assert u1notification != None
            u2notification = UserNotification.query() \
                                .filter(UserNotification.notification ==
                                        notification) \
                                .filter(UserNotification.user_id == self.u2) \
                                .scalar()
            assert u2notification != None

    def test_notification_counter(self):
        with test_context(self.app):
            NotificationModel().create(created_by=self.u1,
                                subject=u'title', body=u'hi there_delete',
                                recipients=[self.u3, self.u1])
            Session().commit()

            assert NotificationModel().get_unread_cnt_for_user(self.u1) == 0
            assert NotificationModel().get_unread_cnt_for_user(self.u2) == 0
            assert NotificationModel().get_unread_cnt_for_user(self.u3) == 1

            notification = NotificationModel().create(created_by=self.u1,
                                               subject=u'title', body=u'hi there3',
                                        recipients=[self.u3, self.u1, self.u2])
            Session().commit()

            assert NotificationModel().get_unread_cnt_for_user(self.u1) == 0
            assert NotificationModel().get_unread_cnt_for_user(self.u2) == 1
            assert NotificationModel().get_unread_cnt_for_user(self.u3) == 2

    @mock.patch.object(h, 'canonical_url', (lambda arg, **kwargs: 'http://%s/?%s' % (arg, '&'.join('%s=%s' % (k, v) for (k, v) in sorted(kwargs.items())))))
    def test_dump_html_mails(self):
        # Exercise all notification types and dump them to one big html file
        l = []

        def send_email(recipients, subject, body='', html_body='', headers=None, author=None):
            l.append('<hr/>\n')
            l.append('<h1>%s</h1>\n' % desc) # desc is from outer scope
            l.append('<pre>\n')
            l.append('From: %s\n' % author.username)
            l.append('To: %s\n' % ' '.join(recipients))
            l.append('Subject: %s\n' % subject)
            l.append('</pre>\n')
            l.append('<hr/>\n')
            l.append('<pre>%s</pre>\n' % body)
            l.append('<hr/>\n')
            l.append(html_body)
            l.append('<hr/>\n')

        with test_context(self.app):
            with mock.patch.object(kallithea.lib.celerylib.tasks, 'send_email', send_email):
                pr_kwargs = dict(
                    pr_nice_id='#7',
                    pr_title='The Title',
                    pr_title_short='The Title',
                    pr_url='http://pr.org/7',
                    pr_target_repo='http://mainline.com/repo',
                    pr_target_branch='trunk',
                    pr_source_repo='https://dev.org/repo',
                    pr_source_branch='devbranch',
                    pr_owner=User.get(self.u2),
                    pr_owner_username='u2'
                    )

                for type_, body, kwargs in [
                        (Notification.TYPE_CHANGESET_COMMENT,
                         u'This is the new \'comment\'.\n\n - and here it ends indented.',
                         dict(
                            short_id='cafe1234',
                            raw_id='cafe1234c0ffeecafe',
                            branch='brunch',
                            cs_comment_user='Opinionated User (jsmith)',
                            cs_comment_url='http://comment.org',
                            is_mention=[False, True],
                            message='This changeset did something clever which is hard to explain',
                            message_short='This changeset did something cl...',
                            status_change=[None, 'Approved'],
                            cs_target_repo='http://example.com/repo_target',
                            cs_url='http://changeset.com',
                            cs_author=User.get(self.u2))),
                        (Notification.TYPE_MESSAGE,
                         u'This is the \'body\' of the "test" message\n - nothing interesting here except indentation.',
                         dict()),
                        #(Notification.TYPE_MENTION, '$body', None), # not used
                        (Notification.TYPE_REGISTRATION,
                         u'Registration body',
                         dict(
                            new_username='newbie',
                            registered_user_url='http://newbie.org',
                            new_email='new@email.com',
                            new_full_name='New Full Name')),
                        (Notification.TYPE_PULL_REQUEST,
                         u'This PR is \'awesome\' because it does <stuff>\n - please approve indented!',
                         dict(
                            pr_user_created='Requesting User (root)', # pr_owner should perhaps be used for @mention in description ...
                            is_mention=[False, True],
                            pr_revisions=[('123abc'*7, "Introduce one and two\n\nand that's it"), ('567fed'*7, 'Make one plus two equal tree')],
                            org_repo_name='repo_org',
                            **pr_kwargs)),
                        (Notification.TYPE_PULL_REQUEST_COMMENT,
                         u'Me too!\n\n - and indented on second line',
                         dict(
                            closing_pr=[False, True],
                            is_mention=[False, True],
                            pr_comment_user='Opinionated User (jsmith)',
                            pr_comment_url='http://pr.org/comment',
                            status_change=[None, 'Under Review'],
                            **pr_kwargs)),
                        ]:
                    kwargs['repo_name'] = u'repo/name'
                    params = [(type_, type_, body, kwargs)]
                    for param_name in ['is_mention', 'status_change', 'closing_pr']: # TODO: inline/general
                        if not isinstance(kwargs.get(param_name), list):
                            continue
                        new_params = []
                        for v in kwargs[param_name]:
                            for desc, type_, body, kwargs in params:
                                kwargs = dict(kwargs)
                                kwargs[param_name] = v
                                new_params.append(('%s, %s=%r' % (desc, param_name, v), type_, body, kwargs))
                        params = new_params

                    for desc, type_, body, kwargs in params:
                        # desc is used as "global" variable
                        notification = NotificationModel().create(created_by=self.u1,
                                                           subject=u'unused', body=body, email_kwargs=kwargs,
                                                           recipients=[self.u2], type_=type_)

                # Email type TYPE_PASSWORD_RESET has no corresponding notification type - test it directly:
                desc = 'TYPE_PASSWORD_RESET'
                kwargs = dict(user='John Doe', reset_token='decbf64715098db5b0bd23eab44bd792670ab746', reset_url='http://reset.com/decbf64715098db5b0bd23eab44bd792670ab746')
                kallithea.lib.celerylib.tasks.send_email(['john@doe.com'],
                    "Password reset link",
                    EmailNotificationModel().get_email_tmpl(EmailNotificationModel.TYPE_PASSWORD_RESET, 'txt', **kwargs),
                    EmailNotificationModel().get_email_tmpl(EmailNotificationModel.TYPE_PASSWORD_RESET, 'html', **kwargs),
                    author=User.get(self.u1))

        out = '<!doctype html>\n<html lang="en">\n<head><title>Notifications</title><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"></head>\n<body>\n%s\n</body>\n</html>\n' % \
            re.sub(r'<(/?(?:!doctype|html|head|title|meta|body)\b[^>]*)>', r'<!--\1-->', ''.join(l))

        outfn = os.path.join(os.path.dirname(__file__), 'test_dump_html_mails.out.html')
        reffn = os.path.join(os.path.dirname(__file__), 'test_dump_html_mails.ref.html')
        with open(outfn, 'w') as f:
            f.write(out)
        with open(reffn) as f:
            ref = f.read()
        assert ref == out # copy test_dump_html_mails.out.html to test_dump_html_mails.ref.html to update expectations
        os.unlink(outfn)
