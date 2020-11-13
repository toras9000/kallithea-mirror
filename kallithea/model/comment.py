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
kallithea.model.comment
~~~~~~~~~~~~~~~~~~~~~~~

comments model for Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Nov 11, 2011
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import logging
from collections import defaultdict

from kallithea.lib import webutils
from kallithea.lib.utils import extract_mentioned_users
from kallithea.model import db, meta, notification


log = logging.getLogger(__name__)


def _list_changeset_commenters(revision):
    return (meta.Session().query(db.User)
        .join(db.ChangesetComment.author)
        .filter(db.ChangesetComment.revision == revision)
        .all())

def _list_pull_request_commenters(pull_request):
    return (meta.Session().query(db.User)
        .join(db.ChangesetComment.author)
        .filter(db.ChangesetComment.pull_request_id == pull_request.pull_request_id)
        .all())


class ChangesetCommentsModel(object):

    def create_notification(self, repo, comment, author, comment_text,
                                line_no=None, revision=None, pull_request=None,
                                status_change=None, closing_pr=False):

        # changeset
        if revision:
            notification_type = notification.NotificationModel.TYPE_CHANGESET_COMMENT
            cs = repo.scm_instance.get_changeset(revision)

            threading = ['%s-rev-%s@%s' % (repo.repo_name, revision, webutils.canonical_hostname())]
            if line_no: # TODO: url to file _and_ line number
                threading.append('%s-rev-%s-line-%s@%s' % (repo.repo_name, revision, line_no,
                                                           webutils.canonical_hostname()))
            comment_url = webutils.canonical_url('changeset_home',
                repo_name=repo.repo_name,
                revision=revision,
                anchor='comment-%s' % comment.comment_id)
            # get the current participants of this changeset
            recipients = _list_changeset_commenters(revision)
            # add changeset author if it's known locally
            cs_author = db.User.get_from_cs_author(cs.author)
            if not cs_author:
                # use repo owner if we cannot extract the author correctly
                # FIXME: just use committer name even if not a user
                cs_author = repo.owner
            recipients.append(cs_author)

            email_kwargs = {
                'status_change': status_change,
                'cs_comment_user': author.full_name_and_username,
                'cs_target_repo': webutils.canonical_url('summary_home', repo_name=repo.repo_name),
                'cs_comment_url': comment_url,
                'cs_url': webutils.canonical_url('changeset_home', repo_name=repo.repo_name, revision=revision),
                'message': cs.message,
                'message_short': webutils.shorter(cs.message, 50, firstline=True),
                'cs_author': cs_author,
                'cs_author_username': cs_author.username,
                'repo_name': repo.repo_name,
                'short_id': revision[:12],
                'branch': cs.branch,
                'threading': threading,
            }
        # pull request
        elif pull_request:
            notification_type = notification.NotificationModel.TYPE_PULL_REQUEST_COMMENT
            _org_ref_type, org_ref_name, _org_rev = comment.pull_request.org_ref.split(':')
            _other_ref_type, other_ref_name, _other_rev = comment.pull_request.other_ref.split(':')
            threading = ['%s-pr-%s@%s' % (pull_request.other_repo.repo_name,
                                          pull_request.pull_request_id,
                                          webutils.canonical_hostname())]
            if line_no: # TODO: url to file _and_ line number
                threading.append('%s-pr-%s-line-%s@%s' % (pull_request.other_repo.repo_name,
                                                          pull_request.pull_request_id, line_no,
                                                          webutils.canonical_hostname()))
            comment_url = pull_request.url(canonical=True,
                anchor='comment-%s' % comment.comment_id)
            # get the current participants of this pull request
            recipients = _list_pull_request_commenters(pull_request)
            recipients.append(pull_request.owner)
            recipients += pull_request.get_reviewer_users()

            # set some variables for email notification
            email_kwargs = {
                'pr_title': pull_request.title,
                'pr_title_short': webutils.shorter(pull_request.title, 50),
                'pr_nice_id': pull_request.nice_id(),
                'status_change': status_change,
                'closing_pr': closing_pr,
                'pr_comment_url': comment_url,
                'pr_url': pull_request.url(canonical=True),
                'pr_comment_user': author.full_name_and_username,
                'pr_target_repo': webutils.canonical_url('summary_home',
                                   repo_name=pull_request.other_repo.repo_name),
                'pr_target_branch': other_ref_name,
                'pr_source_repo': webutils.canonical_url('summary_home',
                                   repo_name=pull_request.org_repo.repo_name),
                'pr_source_branch': org_ref_name,
                'pr_owner': pull_request.owner,
                'pr_owner_username': pull_request.owner.username,
                'repo_name': pull_request.other_repo.repo_name,
                'threading': threading,
            }

        email_kwargs['is_mention'] = False
        # create notification objects, and emails
        notification.NotificationModel().create(
            created_by=author, body=comment_text,
            recipients=recipients, type_=notification_type,
            email_kwargs=email_kwargs,
        )

        mention_recipients = extract_mentioned_users(comment_text).difference(recipients)
        if mention_recipients:
            email_kwargs['is_mention'] = True
            notification.NotificationModel().create(
                created_by=author, body=comment_text,
                recipients=mention_recipients,
                type_=notification_type,
                email_kwargs=email_kwargs
            )


    def create(self, text, repo, author, revision=None, pull_request=None,
               f_path=None, line_no=None, status_change=None, closing_pr=False,
               send_email=True):
        """
        Creates a new comment for either a changeset or a pull request.
        status_change and closing_pr is only for the optional email.

        Returns the created comment.
        """
        if not status_change and not text:
            log.warning('Missing text for comment, skipping...')
            return None

        repo = db.Repository.guess_instance(repo)
        author = db.User.guess_instance(author)
        comment = db.ChangesetComment()
        comment.repo = repo
        comment.author = author
        comment.text = text
        comment.f_path = f_path
        comment.line_no = line_no

        if revision is not None:
            comment.revision = revision
        elif pull_request is not None:
            pull_request = db.PullRequest.guess_instance(pull_request)
            comment.pull_request = pull_request
        else:
            raise Exception('Please specify revision or pull_request_id')

        meta.Session().add(comment)
        meta.Session().flush()

        if send_email:
            self.create_notification(
                repo, comment, author, text, line_no, revision, pull_request,
                status_change, closing_pr
            )

        return comment

    def delete(self, comment):
        comment = db.ChangesetComment.guess_instance(comment)
        meta.Session().delete(comment)

        return comment

    def get_comments(self, repo_id, revision=None, pull_request=None):
        """
        Gets general comments for either revision or pull_request.

        Returns a list, ordered by creation date.
        """
        return self._get_comments(repo_id, revision=revision, pull_request=pull_request,
                                  inline=False)

    def get_inline_comments(self, repo_id, revision=None, pull_request=None,
                f_path=None, line_no=None):
        """
        Gets inline comments for either revision or pull_request.

        Returns a list of tuples with file path and list of comments per line number.
        """
        comments = self._get_comments(repo_id, revision=revision, pull_request=pull_request,
                                      inline=True, f_path=f_path, line_no=line_no)

        paths = defaultdict(lambda: defaultdict(list))
        for co in comments:
            paths[co.f_path][co.line_no].append(co)
        return sorted(paths.items())

    def _get_comments(self, repo_id, revision=None, pull_request=None,
                inline=False, f_path=None, line_no=None):
        """
        Gets comments for either revision or pull_request_id, either inline or general.
        If a file path and optionally line number are given, return only the matching inline comments.
        """
        if f_path is None and line_no is not None:
            raise Exception("line_no only makes sense if f_path is given.")

        if inline is None and f_path is not None:
            raise Exception("f_path only makes sense for inline comments.")

        q = meta.Session().query(db.ChangesetComment)

        if inline:
            if f_path is not None:
                # inline comments for a given file...
                q = q.filter(db.ChangesetComment.f_path == f_path)
                if line_no is None:
                    # ... on any line
                    q = q.filter(db.ChangesetComment.line_no != None)
                else:
                    # ... on specific line
                    q = q.filter(db.ChangesetComment.line_no == line_no)
            else:
                # all inline comments
                q = q.filter(db.ChangesetComment.line_no != None) \
                    .filter(db.ChangesetComment.f_path != None)
        else:
            # all general comments
            q = q.filter(db.ChangesetComment.line_no == None) \
                .filter(db.ChangesetComment.f_path == None)

        if revision is not None:
            q = q.filter(db.ChangesetComment.revision == revision) \
                .filter(db.ChangesetComment.repo_id == repo_id)
        elif pull_request is not None:
            pull_request = db.PullRequest.guess_instance(pull_request)
            q = q.filter(db.ChangesetComment.pull_request == pull_request)
        else:
            raise Exception('Please specify either revision or pull_request')

        return q.order_by(db.ChangesetComment.created_on).all()
