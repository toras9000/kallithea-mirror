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
kallithea.controllers.changeset
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

changeset controller showing changes between revisions

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Apr 25, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import binascii
import logging
import traceback
from collections import OrderedDict

from tg import request, response
from tg import tmpl_context as c
from tg.i18n import ugettext as _
from webob.exc import HTTPBadRequest, HTTPForbidden, HTTPNotFound

import kallithea.lib.helpers as h
from kallithea.controllers import base
from kallithea.lib import auth, diffs, webutils
from kallithea.lib.auth import HasRepoPermissionLevelDecorator, LoginRequired
from kallithea.lib.graphmod import graph_data
from kallithea.lib.utils2 import ascii_str, safe_str
from kallithea.lib.vcs.backends.base import EmptyChangeset
from kallithea.lib.vcs.exceptions import ChangesetDoesNotExistError, EmptyRepositoryError, RepositoryError
from kallithea.model import db, meta, userlog
from kallithea.model.changeset_status import ChangesetStatusModel
from kallithea.model.comment import ChangesetCommentsModel
from kallithea.model.pull_request import PullRequestModel


log = logging.getLogger(__name__)


def create_cs_pr_comment(repo_name, revision=None, pull_request=None, allowed_to_change_status=True):
    """
    Add a comment to the specified changeset or pull request, using POST values
    from the request.

    Comments can be inline (when a file path and line number is specified in
    POST) or general comments.
    A comment can be accompanied by a review status change (accepted, rejected,
    etc.). Pull requests can be closed or deleted.

    Parameter 'allowed_to_change_status' is used for both status changes and
    closing of pull requests. For deleting of pull requests, more specific
    checks are done.
    """

    assert request.environ.get('HTTP_X_PARTIAL_XHR')
    if pull_request:
        pull_request_id = pull_request.pull_request_id
    else:
        pull_request_id = None

    status = request.POST.get('changeset_status')
    close_pr = request.POST.get('save_close')
    delete = request.POST.get('save_delete')
    f_path = request.POST.get('f_path')
    line_no = request.POST.get('line')

    if (status or close_pr or delete) and (f_path or line_no):
        # status votes and closing is only possible in general comments
        raise HTTPBadRequest()

    if not allowed_to_change_status:
        if status or close_pr:
            webutils.flash(_('No permission to change status'), 'error')
            raise HTTPForbidden()

    if pull_request and delete == "delete":
        if (pull_request.owner_id == request.authuser.user_id or
            auth.HasPermissionAny('hg.admin')() or
            auth.HasRepoPermissionLevel('admin')(pull_request.org_repo.repo_name) or
            auth.HasRepoPermissionLevel('admin')(pull_request.other_repo.repo_name)
        ) and not pull_request.is_closed():
            PullRequestModel().delete(pull_request)
            meta.Session().commit()
            webutils.flash(_('Successfully deleted pull request %s') % pull_request_id,
                    category='success')
            return {
               'location': webutils.url('my_pullrequests'), # or repo pr list?
            }
        raise HTTPForbidden()

    text = request.POST.get('text', '').strip()

    comment = ChangesetCommentsModel().create(
        text=text,
        repo=c.db_repo.repo_id,
        author=request.authuser.user_id,
        revision=revision,
        pull_request=pull_request_id,
        f_path=f_path or None,
        line_no=line_no or None,
        status_change=db.ChangesetStatus.get_status_lbl(status) if status else None,
        closing_pr=close_pr,
    )

    if status:
        ChangesetStatusModel().set_status(
            c.db_repo.repo_id,
            status,
            request.authuser.user_id,
            comment,
            revision=revision,
            pull_request=pull_request_id,
        )

    if pull_request:
        action = 'user_commented_pull_request:%s' % pull_request_id
    else:
        action = 'user_commented_revision:%s' % revision
    userlog.action_logger(request.authuser, action, c.db_repo, request.ip_addr)

    if pull_request and close_pr:
        PullRequestModel().close_pull_request(pull_request_id)
        userlog.action_logger(request.authuser,
                      'user_closed_pull_request:%s' % pull_request_id,
                      c.db_repo, request.ip_addr)

    meta.Session().commit()

    data = {
       'target_id': webutils.safeid(request.POST.get('f_path')),
    }
    if comment is not None:
        c.comment = comment
        data.update(comment.get_dict())
        data.update({'rendered_text':
                     base.render('changeset/changeset_comment_block.html')})

    return data

def delete_cs_pr_comment(repo_name, comment_id):
    """Delete a comment from a changeset or pull request"""
    co = db.ChangesetComment.get_or_404(comment_id)
    if co.repo.repo_name != repo_name:
        raise HTTPNotFound()
    if co.pull_request and co.pull_request.is_closed():
        # don't allow deleting comments on closed pull request
        raise HTTPForbidden()

    owner = co.author_id == request.authuser.user_id
    repo_admin = auth.HasRepoPermissionLevel('admin')(repo_name)
    if auth.HasPermissionAny('hg.admin')() or repo_admin or owner:
        ChangesetCommentsModel().delete(comment=co)
        meta.Session().commit()
        return True
    else:
        raise HTTPForbidden()

class ChangesetController(base.BaseRepoController):

    def _before(self, *args, **kwargs):
        super(ChangesetController, self)._before(*args, **kwargs)
        c.affected_files_cut_off = 60

    def _index(self, revision, method):
        c.pull_request = None
        c.fulldiff = request.GET.get('fulldiff') # for reporting number of changed files
        # get ranges of revisions if preset
        rev_range = revision.split('...')[:2]
        c.cs_repo = c.db_repo
        try:
            if len(rev_range) == 2:
                rev_start = rev_range[0]
                rev_end = rev_range[1]
                rev_ranges = c.db_repo_scm_instance.get_changesets(start=rev_start,
                                                             end=rev_end)
            else:
                rev_ranges = [c.db_repo_scm_instance.get_changeset(revision)]

            c.cs_ranges = list(rev_ranges)
            if not c.cs_ranges:
                raise RepositoryError('Changeset range returned empty result')

        except (ChangesetDoesNotExistError, EmptyRepositoryError):
            log.debug(traceback.format_exc())
            msg = _('Such revision does not exist for this repository')
            webutils.flash(msg, category='error')
            raise HTTPNotFound()

        c.changes = OrderedDict()

        c.lines_added = 0  # count of lines added
        c.lines_deleted = 0  # count of lines removes

        c.changeset_statuses = db.ChangesetStatus.STATUSES
        comments = dict()
        c.statuses = []
        c.inline_comments = []
        c.inline_cnt = 0

        # Iterate over ranges (default changeset view is always one changeset)
        for changeset in c.cs_ranges:
            if method == 'show':
                c.statuses.extend([ChangesetStatusModel().get_status(
                            c.db_repo.repo_id, changeset.raw_id)])

                # Changeset comments
                comments.update((com.comment_id, com)
                                for com in ChangesetCommentsModel()
                                .get_comments(c.db_repo.repo_id,
                                              revision=changeset.raw_id))

                # Status change comments - mostly from pull requests
                comments.update((st.comment_id, st.comment)
                                for st in ChangesetStatusModel()
                                .get_statuses(c.db_repo.repo_id,
                                              changeset.raw_id, with_revisions=True)
                                if st.comment_id is not None)

                inlines = ChangesetCommentsModel() \
                            .get_inline_comments(c.db_repo.repo_id,
                                                 revision=changeset.raw_id)
                c.inline_comments.extend(inlines)

            cs2 = changeset.raw_id
            cs1 = changeset.parents[0].raw_id if changeset.parents else EmptyChangeset().raw_id
            ignore_whitespace_diff = h.get_ignore_whitespace_diff(request.GET)
            diff_context_size = h.get_diff_context_size(request.GET)
            raw_diff = diffs.get_diff(c.db_repo_scm_instance, cs1, cs2,
                ignore_whitespace=ignore_whitespace_diff, context=diff_context_size)
            diff_limit = None if c.fulldiff else self.cut_off_limit
            file_diff_data = []
            if method == 'show':
                diff_processor = diffs.DiffProcessor(raw_diff,
                                                     vcs=c.db_repo_scm_instance.alias,
                                                     diff_limit=diff_limit)
                c.limited_diff = diff_processor.limited_diff
                for f in diff_processor.parsed:
                    st = f['stats']
                    c.lines_added += st['added']
                    c.lines_deleted += st['deleted']
                    filename = f['filename']
                    fid = h.FID(changeset.raw_id, filename)
                    url_fid = h.FID('', filename)
                    html_diff = diffs.as_html(parsed_lines=[f])
                    file_diff_data.append((fid, url_fid, f['operation'], f['old_filename'], filename, html_diff, st))
            else:
                # downloads/raw we only need RAW diff nothing else
                file_diff_data.append(('', None, None, None, raw_diff, None))
            c.changes[changeset.raw_id] = (cs1, cs2, file_diff_data)

        # sort comments in creation order
        c.comments = [com for com_id, com in sorted(comments.items())]

        # count inline comments
        for __, lines in c.inline_comments:
            for comments in lines.values():
                c.inline_cnt += len(comments)

        if len(c.cs_ranges) == 1:
            c.changeset = c.cs_ranges[0]
            c.parent_tmpl = ''.join(['# Parent  %s\n' % x.raw_id
                                     for x in c.changeset.parents])
            c.changeset_graft_source_hash = ascii_str(c.changeset.extra.get(b'source', b''))
            c.changeset_transplant_source_hash = ascii_str(binascii.hexlify(c.changeset.extra.get(b'transplant_source', b'')))
        if method == 'download':
            response.content_type = 'text/plain'
            response.content_disposition = 'attachment; filename=%s.diff' \
                                            % revision[:12]
            return raw_diff
        elif method == 'patch':
            response.content_type = 'text/plain'
            c.diff = safe_str(raw_diff)
            return base.render('changeset/patch_changeset.html')
        elif method == 'raw':
            response.content_type = 'text/plain'
            return raw_diff
        elif method == 'show':
            if len(c.cs_ranges) == 1:
                return base.render('changeset/changeset.html')
            else:
                c.cs_ranges_org = None
                c.cs_comments = {}
                revs = [ctx.revision for ctx in reversed(c.cs_ranges)]
                c.jsdata = graph_data(c.db_repo_scm_instance, revs)
                return base.render('changeset/changeset_range.html')

    @LoginRequired(allow_default_user=True)
    @HasRepoPermissionLevelDecorator('read')
    def index(self, revision, method='show'):
        return self._index(revision, method=method)

    @LoginRequired(allow_default_user=True)
    @HasRepoPermissionLevelDecorator('read')
    def changeset_raw(self, revision):
        return self._index(revision, method='raw')

    @LoginRequired(allow_default_user=True)
    @HasRepoPermissionLevelDecorator('read')
    def changeset_patch(self, revision):
        return self._index(revision, method='patch')

    @LoginRequired(allow_default_user=True)
    @HasRepoPermissionLevelDecorator('read')
    def changeset_download(self, revision):
        return self._index(revision, method='download')

    @LoginRequired()
    @HasRepoPermissionLevelDecorator('read')
    @base.jsonify
    def comment(self, repo_name, revision):
        return create_cs_pr_comment(repo_name, revision=revision)

    @LoginRequired()
    @HasRepoPermissionLevelDecorator('read')
    @base.jsonify
    def delete_comment(self, repo_name, comment_id):
        return delete_cs_pr_comment(repo_name, comment_id)

    @LoginRequired(allow_default_user=True)
    @HasRepoPermissionLevelDecorator('read')
    @base.jsonify
    def changeset_info(self, repo_name, revision):
        if request.is_xhr:
            try:
                return c.db_repo_scm_instance.get_changeset(revision)
            except ChangesetDoesNotExistError as e:
                return EmptyChangeset(message=str(e))
        else:
            raise HTTPBadRequest()

    @LoginRequired(allow_default_user=True)
    @HasRepoPermissionLevelDecorator('read')
    @base.jsonify
    def changeset_children(self, repo_name, revision):
        if request.is_xhr:
            changeset = c.db_repo_scm_instance.get_changeset(revision)
            result = {"results": []}
            if changeset.children:
                result = {"results": changeset.children}
            return result
        else:
            raise HTTPBadRequest()

    @LoginRequired(allow_default_user=True)
    @HasRepoPermissionLevelDecorator('read')
    @base.jsonify
    def changeset_parents(self, repo_name, revision):
        if request.is_xhr:
            changeset = c.db_repo_scm_instance.get_changeset(revision)
            result = {"results": []}
            if changeset.parents:
                result = {"results": changeset.parents}
            return result
        else:
            raise HTTPBadRequest()
