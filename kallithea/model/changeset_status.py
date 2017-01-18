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
kallithea.model.changeset_status
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Changeset status controller

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Apr 30, 2012
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import logging
from sqlalchemy.orm import joinedload

from kallithea.model.base import BaseModel
from kallithea.model.db import ChangesetStatus, PullRequest, User
from kallithea.lib.exceptions import StatusChangeOnClosedPullRequestError

log = logging.getLogger(__name__)


class ChangesetStatusModel(BaseModel):

    def _get_status_query(self, repo, revision, pull_request,
                          with_revisions=False):
        repo = self._get_repo(repo)

        q = ChangesetStatus.query() \
            .filter(ChangesetStatus.repo == repo)
        if not with_revisions:
            # only report the latest vote across all users! TODO: be smarter!
            q = q.filter(ChangesetStatus.version == 0)

        if revision:
            q = q.filter(ChangesetStatus.revision == revision)
        elif pull_request:
            pull_request = PullRequest.guess_instance(pull_request)
            q = q.filter(ChangesetStatus.pull_request == pull_request)
        else:
            raise Exception('Please specify revision or pull_request')
        q = q.order_by(ChangesetStatus.version.asc())
        return q

    def _calculate_status(self, statuses):
        """
        Given a list of statuses, calculate the resulting status, according to
        the policy: approve if consensus, reject when at least one reject.
        """

        if not statuses:
            return ChangesetStatus.STATUS_UNDER_REVIEW

        if all(st and st.status == ChangesetStatus.STATUS_APPROVED for st in statuses):
            return ChangesetStatus.STATUS_APPROVED

        if any(st and st.status == ChangesetStatus.STATUS_REJECTED for st in statuses):
            return ChangesetStatus.STATUS_REJECTED

        return ChangesetStatus.STATUS_UNDER_REVIEW

    def calculate_pull_request_result(self, pull_request):
        """
        Return a tuple (reviewers, pending reviewers, pull request status)
        Only approve and reject counts as valid votes.
        """

        # collect latest votes from all voters
        cs_statuses = dict()
        for st in reversed(self.get_statuses(pull_request.org_repo,
                                             pull_request=pull_request,
                                             with_revisions=True)):
            cs_statuses[st.author.username] = st

        # collect votes from official reviewers
        pull_request_reviewers = []
        pull_request_pending_reviewers = []
        relevant_statuses = []
        for user in pull_request.get_reviewer_users():
            st = cs_statuses.get(user.username)
            relevant_statuses.append(st)
            status = ChangesetStatus.STATUS_NOT_REVIEWED if st is None else st.status
            if status in (ChangesetStatus.STATUS_NOT_REVIEWED,
                          ChangesetStatus.STATUS_UNDER_REVIEW):
                pull_request_pending_reviewers.append(user)
            pull_request_reviewers.append((user, status))

        result = self._calculate_status(relevant_statuses)

        return (pull_request_reviewers,
                pull_request_pending_reviewers,
                result)

    def get_statuses(self, repo, revision=None, pull_request=None,
                     with_revisions=False):
        q = self._get_status_query(repo, revision, pull_request,
                                   with_revisions)
        q = q.options(joinedload('author'))
        return q.all()

    def get_status(self, repo, revision=None, pull_request=None, as_str=True):
        """
        Returns latest status of changeset for given revision or for given
        pull request. Statuses are versioned inside a table itself and
        version == 0 is always the current one

        :param repo:
        :param revision: 40char hash or None
        :param pull_request: pull_request reference
        :param as_str: return status as string not object
        """
        q = self._get_status_query(repo, revision, pull_request)

        # need to use first here since there can be multiple statuses
        # returned from pull_request
        status = q.first()
        if as_str:
            return str(status.status) if status else ChangesetStatus.DEFAULT
        return status

    def set_status(self, repo, status, user, comment, revision=None,
                   pull_request=None, dont_allow_on_closed_pull_request=False):
        """
        Creates new status for changeset or updates the old ones bumping their
        version, leaving the current status at the value of 'status'.

        :param repo:
        :param status:
        :param user:
        :param comment:
        :param revision:
        :param pull_request:
        :param dont_allow_on_closed_pull_request: don't allow a status change
            if last status was for pull request and it's closed. We shouldn't
            mess around this manually
        """
        repo = self._get_repo(repo)

        q = ChangesetStatus.query()
        if revision is not None:
            assert pull_request is None
            q = q.filter(ChangesetStatus.repo == repo)
            q = q.filter(ChangesetStatus.revision == revision)
            revisions = [revision]
        else:
            assert pull_request is not None
            pull_request = PullRequest.guess_instance(pull_request)
            repo = pull_request.org_repo
            q = q.filter(ChangesetStatus.repo == repo)
            q = q.filter(ChangesetStatus.revision.in_(pull_request.revisions))
            revisions = pull_request.revisions
        cur_statuses = q.all()

        #if statuses exists and last is associated with a closed pull request
        # we need to check if we can allow this status change
        if (dont_allow_on_closed_pull_request and cur_statuses
            and getattr(cur_statuses[0].pull_request, 'status', '')
                == PullRequest.STATUS_CLOSED):
            raise StatusChangeOnClosedPullRequestError(
                'Changing status on closed pull request is not allowed'
            )

        #update all current statuses with older version
        for st in cur_statuses:
            st.version += 1
            self.sa.add(st)

        new_statuses = []
        for rev in revisions:
            new_status = ChangesetStatus()
            new_status.version = 0 # default
            new_status.author = User.guess_instance(user)
            new_status.repo = self._get_repo(repo)
            new_status.status = status
            new_status.comment = comment
            new_status.revision = rev
            new_status.pull_request = pull_request
            new_statuses.append(new_status)
            self.sa.add(new_status)
        return new_statuses
