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
kallithea.model.pull_request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

pull request model for Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Jun 6, 2012
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import datetime
import logging
import re

from tg import request
from tg.i18n import ugettext as _

from kallithea.lib import auth, hooks, webutils
from kallithea.lib.utils import extract_mentioned_users
from kallithea.lib.utils2 import ascii_bytes, short_ref_name
from kallithea.model import changeset_status, comment, db, meta, notification


log = logging.getLogger(__name__)


def _assert_valid_reviewers(seq):
    """Sanity check: elements are actual User objects, and not the default user."""
    assert not any(user.is_default_user for user in seq)


class PullRequestModel(object):

    def add_reviewers(self, user, pr, reviewers, mention_recipients=None):
        """Add reviewer and send notification to them.
        """
        reviewers = set(reviewers)
        _assert_valid_reviewers(reviewers)
        if mention_recipients is not None:
            mention_recipients = set(mention_recipients) - reviewers
            _assert_valid_reviewers(mention_recipients)

        redundant_reviewers = set(db.User.query() \
            .join(db.PullRequestReviewer) \
            .filter(db.PullRequestReviewer.pull_request == pr) \
            .filter(db.PullRequestReviewer.user_id.in_(r.user_id for r in reviewers))
            .all())

        if redundant_reviewers:
            log.debug('Following reviewers were already part of pull request %s: %s', pr.pull_request_id, redundant_reviewers)

            reviewers -= redundant_reviewers

        log.debug('Adding reviewers to pull request %s: %s', pr.pull_request_id, reviewers)
        for reviewer in reviewers:
            prr = db.PullRequestReviewer(reviewer, pr)
            meta.Session().add(prr)

        # notification to reviewers
        pr_url = pr.url(canonical=True)
        threading = ['%s-pr-%s@%s' % (pr.other_repo.repo_name,
                                      pr.pull_request_id,
                                      webutils.canonical_hostname())]
        body = pr.description
        _org_ref_type, org_ref_name, _org_rev = pr.org_ref.split(':')
        _other_ref_type, other_ref_name, _other_rev = pr.other_ref.split(':')
        revision_data = [(x.raw_id, x.message)
                         for x in map(pr.org_repo.get_changeset, pr.revisions)]
        email_kwargs = {
            'pr_title': pr.title,
            'pr_title_short': webutils.shorter(pr.title, 50),
            'pr_user_created': user.full_name_and_username,
            'pr_repo_url': webutils.canonical_url('summary_home', repo_name=pr.other_repo.repo_name),
            'pr_url': pr_url,
            'pr_revisions': revision_data,
            'repo_name': pr.other_repo.repo_name,
            'org_repo_name': pr.org_repo.repo_name,
            'pr_nice_id': pr.nice_id(),
            'pr_target_repo': webutils.canonical_url('summary_home',
                               repo_name=pr.other_repo.repo_name),
            'pr_target_branch': other_ref_name,
            'pr_source_repo': webutils.canonical_url('summary_home',
                               repo_name=pr.org_repo.repo_name),
            'pr_source_branch': org_ref_name,
            'pr_owner': pr.owner,
            'pr_owner_username': pr.owner.username,
            'pr_username': user.username,
            'threading': threading,
            'is_mention': False,
            }
        if reviewers:
            notification.NotificationModel().create(created_by=user, body=body,
                                       recipients=reviewers,
                                       type_=notification.NotificationModel.TYPE_PULL_REQUEST,
                                       email_kwargs=email_kwargs)

        if mention_recipients:
            email_kwargs['is_mention'] = True
            notification.NotificationModel().create(created_by=user, body=body,
                                       recipients=mention_recipients,
                                       type_=notification.NotificationModel.TYPE_PULL_REQUEST,
                                       email_kwargs=email_kwargs)

        return reviewers, redundant_reviewers

    def mention_from_description(self, user, pr, old_description=''):
        mention_recipients = (extract_mentioned_users(pr.description) -
                              extract_mentioned_users(old_description))

        log.debug("Mentioning %s", mention_recipients)
        self.add_reviewers(user, pr, set(), mention_recipients)

    def remove_reviewers(self, user, pull_request, reviewers):
        """Remove specified users from being reviewers of the PR."""
        if not reviewers:
            return # avoid SQLAlchemy warning about empty sequence for IN-predicate

        db.PullRequestReviewer.query() \
            .filter_by(pull_request=pull_request) \
            .filter(db.PullRequestReviewer.user_id.in_(r.user_id for r in reviewers)) \
            .delete(synchronize_session='fetch') # the default of 'evaluate' is not available

    def delete(self, pull_request):
        pull_request = db.PullRequest.guess_instance(pull_request)
        meta.Session().delete(pull_request)
        if pull_request.org_repo.scm_instance.alias == 'git':
            # remove a ref under refs/pull/ so that commits can be garbage-collected
            try:
                del pull_request.org_repo.scm_instance._repo[b"refs/pull/%d/head" % pull_request.pull_request_id]
            except KeyError:
                pass

    def close_pull_request(self, pull_request):
        pull_request = db.PullRequest.guess_instance(pull_request)
        pull_request.status = db.PullRequest.STATUS_CLOSED
        pull_request.updated_on = datetime.datetime.now()


class CreatePullRequestAction(object):

    class ValidationError(Exception):
        pass

    class Empty(ValidationError):
        pass

    class AmbiguousAncestor(ValidationError):
        pass

    class Unauthorized(ValidationError):
        pass

    @staticmethod
    def is_user_authorized(org_repo, other_repo):
        """Performs authorization check with only the minimum amount of
        information needed for such a check, rather than a full command
        object.
        """
        if (auth.HasRepoPermissionLevel('read')(org_repo.repo_name) and
            auth.HasRepoPermissionLevel('read')(other_repo.repo_name)
        ):
            return True

        return False

    def __init__(self, org_repo, other_repo, org_ref, other_ref, title, description, owner, reviewers):
        reviewers = set(reviewers)
        _assert_valid_reviewers(reviewers)

        (org_ref_type,
         org_ref_name,
         org_rev) = org_ref.split(':')
        org_display = short_ref_name(org_ref_type, org_ref_name)
        if org_ref_type == 'rev':
            cs = org_repo.scm_instance.get_changeset(org_rev)
            org_ref = 'branch:%s:%s' % (cs.branch, cs.raw_id)

        (other_ref_type,
         other_ref_name,
         other_rev) = other_ref.split(':')
        if other_ref_type == 'rev':
            cs = other_repo.scm_instance.get_changeset(other_rev)
            other_ref_name = cs.raw_id[:12]
            other_ref = '%s:%s:%s' % (other_ref_type, other_ref_name, cs.raw_id)
        other_display = short_ref_name(other_ref_type, other_ref_name)

        cs_ranges, _cs_ranges_not, ancestor_revs = \
            org_repo.scm_instance.get_diff_changesets(other_rev, org_repo.scm_instance, org_rev) # org and other "swapped"
        if not cs_ranges:
            raise self.Empty(_('Cannot create empty pull request'))

        if not ancestor_revs:
            ancestor_rev = org_repo.scm_instance.EMPTY_CHANGESET
        elif len(ancestor_revs) == 1:
            ancestor_rev = ancestor_revs[0]
        else:
            raise self.AmbiguousAncestor(
                _('Cannot create pull request - criss cross merge detected, please merge a later %s revision to %s')
                % (other_ref_name, org_ref_name))

        self.revisions = [cs_.raw_id for cs_ in cs_ranges]

        # hack: ancestor_rev is not an other_rev but we want to show the
        # requested destination and have the exact ancestor
        other_ref = '%s:%s:%s' % (other_ref_type, other_ref_name, ancestor_rev)

        if not title:
            if org_repo == other_repo:
                title = '%s to %s' % (org_display, other_display)
            else:
                title = '%s#%s to %s#%s' % (org_repo.repo_name, org_display,
                                            other_repo.repo_name, other_display)
        description = description or _('No description')

        self.org_repo = org_repo
        self.other_repo = other_repo
        self.org_ref = org_ref
        self.org_rev = org_rev
        self.other_ref = other_ref
        self.title = title
        self.description = description
        self.owner = owner
        self.reviewers = reviewers

        if not CreatePullRequestAction.is_user_authorized(self.org_repo, self.other_repo):
            raise self.Unauthorized(_('You are not authorized to create the pull request'))

    def execute(self):
        created_by = db.User.get(request.authuser.user_id)

        pr = db.PullRequest()
        pr.org_repo = self.org_repo
        pr.org_ref = self.org_ref
        pr.other_repo = self.other_repo
        pr.other_ref = self.other_ref
        pr.revisions = self.revisions
        pr.title = self.title
        pr.description = self.description
        pr.owner = self.owner
        meta.Session().add(pr)
        meta.Session().flush() # make database assign pull_request_id

        if self.org_repo.scm_instance.alias == 'git':
            # create a ref under refs/pull/ so that commits don't get garbage-collected
            self.org_repo.scm_instance._repo[b"refs/pull/%d/head" % pr.pull_request_id] = ascii_bytes(self.org_rev)

        # reset state to under-review
        new_comment = comment.ChangesetCommentsModel().create(
            text='',
            repo=self.org_repo,
            author=created_by,
            pull_request=pr,
            send_email=False,
            status_change=db.ChangesetStatus.STATUS_UNDER_REVIEW,
        )
        changeset_status.ChangesetStatusModel().set_status(
            self.org_repo,
            db.ChangesetStatus.STATUS_UNDER_REVIEW,
            created_by,
            new_comment,
            pull_request=pr,
        )

        mention_recipients = extract_mentioned_users(self.description)
        PullRequestModel().add_reviewers(created_by, pr, self.reviewers, mention_recipients)

        hooks.log_create_pullrequest(pr.get_dict(), created_by)

        return pr


class CreatePullRequestIterationAction(object):
    @staticmethod
    def is_user_authorized(old_pull_request):
        """Performs authorization check with only the minimum amount of
        information needed for such a check, rather than a full command
        object.
        """
        if auth.HasPermissionAny('hg.admin')():
            return True

        # Authorized to edit the old PR?
        if request.authuser.user_id != old_pull_request.owner_id:
            return False

        # Authorized to create a new PR?
        if not CreatePullRequestAction.is_user_authorized(old_pull_request.org_repo, old_pull_request.other_repo):
            return False

        return True

    def __init__(self, old_pull_request, new_org_rev, new_other_rev, title, description, owner, reviewers):
        self.old_pull_request = old_pull_request

        org_repo = old_pull_request.org_repo
        org_ref_type, org_ref_name, org_rev = old_pull_request.org_ref.split(':')

        other_repo = old_pull_request.other_repo
        other_ref_type, other_ref_name, other_rev = old_pull_request.other_ref.split(':') # other_rev is ancestor
        #assert other_ref_type == 'branch', other_ref_type # TODO: what if not?

        new_org_ref = '%s:%s:%s' % (org_ref_type, org_ref_name, new_org_rev)
        new_other_ref = '%s:%s:%s' % (other_ref_type, other_ref_name, new_other_rev)

        self.create_action = CreatePullRequestAction(org_repo, other_repo, new_org_ref, new_other_ref, None, None, owner, reviewers)

        # Generate complete title/description

        old_revisions = set(old_pull_request.revisions)
        revisions = self.create_action.revisions
        new_revisions = [r for r in revisions if r not in old_revisions]
        lost = old_revisions.difference(revisions)

        infos = ['This is a new iteration of %s "%s".' %
                 (webutils.canonical_url('pullrequest_show', repo_name=old_pull_request.other_repo.repo_name,
                      pull_request_id=old_pull_request.pull_request_id),
                  old_pull_request.title)]

        if lost:
            infos.append(_('Missing changesets since the previous iteration:'))
            for r in old_pull_request.revisions:
                if r in lost:
                    rev_desc = org_repo.get_changeset(r).message.split('\n')[0]
                    infos.append('  %s %s' % (r[:12], rev_desc))

        if new_revisions:
            infos.append(_('New changesets on %s %s since the previous iteration:') % (org_ref_type, org_ref_name))
            for r in reversed(revisions):
                if r in new_revisions:
                    rev_desc = org_repo.get_changeset(r).message.split('\n')[0]
                    infos.append('  %s %s' % (r[:12], webutils.shorter(rev_desc, 80)))

            if self.create_action.other_ref == old_pull_request.other_ref:
                infos.append(_("Ancestor didn't change - diff since previous iteration:"))
                infos.append(webutils.canonical_url('compare_url',
                                 repo_name=org_repo.repo_name, # other_repo is always same as repo_name
                                 org_ref_type='rev', org_ref_name=org_rev[:12], # use old org_rev as base
                                 other_ref_type='rev', other_ref_name=new_org_rev[:12],
                                 )) # note: linear diff, merge or not doesn't matter
            else:
                infos.append(_('This iteration is based on another %s revision and there is no simple diff.') % other_ref_name)
        else:
            infos.append(_('No changes found on %s %s since previous iteration.') % (org_ref_type, org_ref_name))
            # TODO: fail?

        v = 2
        m = re.match(r'(.*)\(v(\d+)\)\s*$', title)
        if m is not None:
            title = m.group(1)
            v = int(m.group(2)) + 1
        self.create_action.title = '%s (v%s)' % (title.strip(), v)

        # using a mail-like separator, insert new iteration info in description with latest first
        descriptions = description.replace('\r\n', '\n').split('\n-- \n', 1)
        description = descriptions[0].strip() + '\n\n-- \n' + '\n'.join(infos)
        if len(descriptions) > 1:
            description += '\n\n' + descriptions[1].strip()
        self.create_action.description = description

        if not CreatePullRequestIterationAction.is_user_authorized(self.old_pull_request):
            raise CreatePullRequestAction.Unauthorized(_('You are not authorized to create the pull request'))

    def execute(self):
        pull_request = self.create_action.execute()

        # Close old iteration
        comment.ChangesetCommentsModel().create(
            text=_('Closed, next iteration: %s .') % pull_request.url(canonical=True),
            repo=self.old_pull_request.other_repo_id,
            author=request.authuser.user_id,
            pull_request=self.old_pull_request.pull_request_id,
            closing_pr=True)
        PullRequestModel().close_pull_request(self.old_pull_request.pull_request_id)
        return pull_request
