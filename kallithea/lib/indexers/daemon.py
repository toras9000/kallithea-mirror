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
kallithea.lib.indexers.daemon
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A daemon will read from task table and run tasks

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Jan 26, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""


import logging
import os
import traceback
from shutil import rmtree
from time import mktime

from tg import config
from whoosh.index import create_in, exists_in, open_dir
from whoosh.qparser import QueryParser

from kallithea.lib import celerylib
from kallithea.lib.conf import INDEX_EXTENSIONS, INDEX_FILENAMES
from kallithea.lib.indexers import CHGSET_IDX_NAME, CHGSETS_SCHEMA, IDX_NAME, SCHEMA
from kallithea.lib.utils2 import safe_str
from kallithea.lib.vcs.exceptions import ChangesetDoesNotExistError, ChangesetError, NodeDoesNotExistError, RepositoryError
from kallithea.model import db
from kallithea.model.scm import ScmModel


log = logging.getLogger('whoosh_indexer')


class WhooshIndexingDaemon(object):
    """
    Daemon for atomic indexing jobs
    """

    def __init__(self, indexname=IDX_NAME, index_location=None,
                 repo_location=None, repo_list=None,
                 repo_update_list=None):
        self.indexname = indexname

        self.index_location = index_location
        if not index_location:
            raise Exception('You have to provide index location')

        self.repo_location = repo_location
        if not repo_location:
            raise Exception('You have to provide repositories location')

        self.repo_paths = ScmModel().repo_scan(self.repo_location)

        # filter repo list
        if repo_list:
            repo_list = set(repo_list)
            self.filtered_repo_paths = {}
            for repo_name, repo in self.repo_paths.items():
                if repo_name in repo_list:
                    self.filtered_repo_paths[repo_name] = repo

            self.repo_paths = self.filtered_repo_paths

        # filter update repo list
        self.filtered_repo_update_paths = {}
        if repo_update_list:
            self.filtered_repo_update_paths = {}
            for repo_name, repo in self.repo_paths.items():
                if repo_name in repo_update_list:
                    self.filtered_repo_update_paths[repo_name] = repo
            self.repo_paths = self.filtered_repo_update_paths

        self.initial = True
        if not os.path.isdir(self.index_location):
            os.makedirs(self.index_location)
            log.info('Cannot run incremental index since it does not '
                     'yet exist - running full build')
        elif not exists_in(self.index_location, IDX_NAME):
            log.info('Running full index build, as the file content '
                     'index does not exist')
        elif not exists_in(self.index_location, CHGSET_IDX_NAME):
            log.info('Running full index build, as the changeset '
                     'index does not exist')
        else:
            self.initial = False

    def _get_index_revision(self, repo):
        db_repo = db.Repository.get_by_repo_name(repo.name)
        landing_rev = 'tip'
        if db_repo:
            _rev_type, _rev = db_repo.landing_rev
            landing_rev = _rev
        return landing_rev

    def _get_index_changeset(self, repo, index_rev=None):
        if not index_rev:
            index_rev = self._get_index_revision(repo)
        cs = repo.get_changeset(index_rev)
        return cs

    def get_paths(self, repo):
        """
        recursive walk in root dir and return a set of all path in that dir
        based on repository walk function
        """
        index_paths_ = set()
        try:
            cs = self._get_index_changeset(repo)
            for _topnode, _dirs, files in cs.walk('/'):
                for f in files:
                    index_paths_.add(os.path.join(repo.path, f.path))

        except RepositoryError:
            log.debug(traceback.format_exc())
            pass
        return index_paths_

    def get_node(self, repo, path, index_rev=None):
        """
        gets a filenode based on given full path.

        :param repo: scm repo instance
        :param path: full path including root location
        :return: FileNode
        """
        # FIXME: paths should be normalized ... or even better: don't include repo.path
        assert path.startswith(repo.path)
        assert path[len(repo.path)] in (os.path.sep, os.path.altsep)
        node_path = path[len(repo.path) + 1:]
        cs = self._get_index_changeset(repo, index_rev=index_rev)
        node = cs.get_node(node_path)
        return node

    def is_indexable_node(self, node):
        """
        Just index the content of chosen files, skipping binary files
        """
        return (node.extension in INDEX_EXTENSIONS or node.name in INDEX_FILENAMES) and \
               not node.is_binary

    def get_node_mtime(self, node):
        return mktime(node.last_changeset.date.timetuple())

    def add_doc(self, writer, path, repo, repo_name, index_rev=None):
        """
        Adding doc to writer this function itself fetches data from
        the instance of vcs backend
        """
        try:
            node = self.get_node(repo, path, index_rev)
        except (ChangesetError, NodeDoesNotExistError):
            log.debug("    >> %s - not found in %s %s", path, repo, index_rev)
            return 0, 0

        indexed = indexed_w_content = 0
        if self.is_indexable_node(node):
            bytes_content = node.content
            if b'\0' in bytes_content:
                log.warning('    >> %s - no text content', path)
                u_content = ''
            else:
                log.debug('    >> %s', path)
                u_content = safe_str(bytes_content)
                indexed_w_content += 1

        else:
            log.debug('    >> %s - not indexable', path)
            # just index file name without it's content
            u_content = ''
            indexed += 1

        writer.add_document(
            fileid=path,
            repository_rawname=repo_name,
            repository=repo_name,
            path=path,
            content=u_content,
            modtime=self.get_node_mtime(node),
            extension=node.extension
        )
        return indexed, indexed_w_content

    def index_changesets(self, writer, repo_name, repo, start_rev=None):
        """
        Add all changeset in the vcs repo starting at start_rev
        to the index writer

        :param writer: the whoosh index writer to add to
        :param repo_name: name of the repository from whence the
          changeset originates including the repository group
        :param repo: the vcs repository instance to index changesets for,
          the presumption is the repo has changesets to index
        :param start_rev=None: the full sha id to start indexing from
          if start_rev is None then index from the first changeset in
          the repo
        """

        if start_rev is None:
            start_rev = repo[0].raw_id

        log.debug('Indexing changesets in %s, starting at rev %s',
                  repo_name, start_rev)

        indexed = 0
        cs_iter = repo.get_changesets(start=start_rev)
        total = len(cs_iter)
        for cs in cs_iter:
            indexed += 1
            log.debug('    >> %s %s/%s', cs, indexed, total)
            writer.add_document(
                raw_id=cs.raw_id,
                date=cs._timestamp,
                repository_rawname=repo_name,
                repository=repo_name,
                author=cs.author,
                message=cs.message,
                last=cs.last,
                added=' '.join(node.path for node in cs.added).lower(),
                removed=' '.join(node.path for node in cs.removed).lower(),
                changed=' '.join(node.path for node in cs.changed).lower(),
                parents=' '.join(cs.raw_id for cs in cs.parents),
            )

        return indexed

    def index_files(self, file_idx_writer, repo_name, repo):
        """
        Index files for given repo_name

        :param file_idx_writer: the whoosh index writer to add to
        :param repo_name: name of the repository we're indexing
        :param repo: instance of vcs repo
        """
        i_cnt = iwc_cnt = 0
        log.debug('Building file index for %s @revision:%s', repo_name,
                                                self._get_index_revision(repo))
        index_rev = self._get_index_revision(repo)
        for idx_path in self.get_paths(repo):
            i, iwc = self.add_doc(file_idx_writer, idx_path, repo, repo_name, index_rev)
            i_cnt += i
            iwc_cnt += iwc

        log.debug('added %s files %s with content for repo %s',
                  i_cnt + iwc_cnt, iwc_cnt, repo.path)
        return i_cnt, iwc_cnt

    def update_changeset_index(self):
        idx = open_dir(self.index_location, indexname=CHGSET_IDX_NAME)

        with idx.searcher() as searcher:
            writer = idx.writer()
            writer_is_dirty = False
            try:
                indexed_total = 0
                repo_name = None
                for repo_name, repo in sorted(self.repo_paths.items()):
                    log.debug('Updating changeset index for repo %s', repo_name)
                    # skip indexing if there aren't any revs in the repo
                    num_of_revs = len(repo)
                    if num_of_revs < 1:
                        continue

                    qp = QueryParser('repository', schema=CHGSETS_SCHEMA)
                    q = qp.parse("last:t AND %s" % repo_name)

                    results = searcher.search(q)

                    # default to scanning the entire repo
                    last_rev = 0
                    start_id = None

                    if len(results) > 0:
                        # assuming that there is only one result, if not this
                        # may require a full re-index.
                        start_id = results[0]['raw_id']
                        try:
                            last_rev = repo.get_changeset(revision=start_id).revision
                        except ChangesetDoesNotExistError:
                            log.error('previous last revision %s not found - indexing from scratch', start_id)
                            start_id = None

                    # there are new changesets to index or a new repo to index
                    if last_rev == 0 or num_of_revs > last_rev + 1:
                        # delete the docs in the index for the previous
                        # last changeset(s)
                        for hit in results:
                            q = qp.parse("last:t AND %s AND raw_id:%s" %
                                            (repo_name, hit['raw_id']))
                            writer.delete_by_query(q)

                        # index from the previous last changeset + all new ones
                        indexed_total += self.index_changesets(writer,
                                                repo_name, repo, start_id)
                        writer_is_dirty = True
                log.debug('indexed %s changesets for repo %s',
                          indexed_total, repo_name
                )
            finally:
                if writer_is_dirty:
                    log.debug('>> COMMITING CHANGES TO CHANGESET INDEX<<')
                    writer.commit(merge=True)
                    log.debug('>>> FINISHED REBUILDING CHANGESET INDEX <<<')
                else:
                    log.debug('>> NOTHING TO COMMIT TO CHANGESET INDEX<<')

    def update_file_index(self):
        log.debug('STARTING INCREMENTAL INDEXING UPDATE FOR EXTENSIONS %s '
                  'AND REPOS %s', INDEX_EXTENSIONS, ' and '.join(self.repo_paths))

        idx = open_dir(self.index_location, indexname=self.indexname)
        # The set of all paths in the index
        indexed_paths = set()
        # The set of all paths we need to re-index
        to_index = set()

        writer = idx.writer()
        writer_is_dirty = False
        try:
            with idx.reader() as reader:

                # Loop over the stored fields in the index
                for fields in reader.all_stored_fields():
                    indexed_path = fields['path']
                    indexed_repo_path = fields['repository']
                    indexed_paths.add(indexed_path)

                    if indexed_repo_path not in self.filtered_repo_update_paths:
                        continue

                    repo = self.repo_paths[indexed_repo_path]

                    try:
                        node = self.get_node(repo, indexed_path)
                        # Check if this file was changed since it was indexed
                        indexed_time = fields['modtime']
                        mtime = self.get_node_mtime(node)
                        if mtime > indexed_time:
                            # The file has changed, delete it and add it to
                            # the list of files to reindex
                            log.debug(
                                'adding to reindex list %s mtime: %s vs %s',
                                    indexed_path, mtime, indexed_time
                            )
                            writer.delete_by_term('fileid', indexed_path)
                            writer_is_dirty = True

                            to_index.add(indexed_path)
                    except (ChangesetError, NodeDoesNotExistError):
                        # This file was deleted since it was indexed
                        log.debug('removing from index %s', indexed_path)
                        writer.delete_by_term('path', indexed_path)
                        writer_is_dirty = True

            # Loop over the files in the filesystem
            # Assume we have a function that gathers the filenames of the
            # documents to be indexed
            ri_cnt_total = 0  # indexed
            riwc_cnt_total = 0  # indexed with content
            for repo_name, repo in sorted(self.repo_paths.items()):
                log.debug('Updating file index for repo %s', repo_name)
                # skip indexing if there aren't any revisions
                if len(repo) < 1:
                    continue
                ri_cnt = 0   # indexed
                riwc_cnt = 0  # indexed with content
                for path in self.get_paths(repo):
                    if path in to_index or path not in indexed_paths:
                        # This is either a file that's changed, or a new file
                        # that wasn't indexed before. So index it!
                        i, iwc = self.add_doc(writer, path, repo, repo_name)
                        writer_is_dirty = True
                        ri_cnt += i
                        ri_cnt_total += 1
                        riwc_cnt += iwc
                        riwc_cnt_total += iwc
                log.debug('added %s files %s with content for repo %s',
                             ri_cnt + riwc_cnt, riwc_cnt, repo.path
                )
            log.debug('indexed %s files in total and %s with content',
                        ri_cnt_total, riwc_cnt_total
            )
        finally:
            if writer_is_dirty:
                log.debug('>> COMMITING CHANGES TO FILE INDEX <<')
                writer.commit(merge=True)
                log.debug('>>> FINISHED REBUILDING FILE INDEX <<<')
            else:
                log.debug('>> NOTHING TO COMMIT TO FILE INDEX <<')
                writer.cancel()

    def build_indexes(self):
        if os.path.exists(self.index_location):
            log.debug('removing previous index')
            rmtree(self.index_location)

        if not os.path.exists(self.index_location):
            os.mkdir(self.index_location)

        chgset_idx = create_in(self.index_location, CHGSETS_SCHEMA,
                               indexname=CHGSET_IDX_NAME)
        chgset_idx_writer = chgset_idx.writer()

        file_idx = create_in(self.index_location, SCHEMA, indexname=IDX_NAME)
        file_idx_writer = file_idx.writer()
        log.debug('BUILDING INDEX FOR EXTENSIONS %s '
                  'AND REPOS %s', INDEX_EXTENSIONS, ' and '.join(self.repo_paths))

        for repo_name, repo in sorted(self.repo_paths.items()):
            log.debug('Updating indices for repo %s', repo_name)
            # skip indexing if there aren't any revisions
            if len(repo) < 1:
                continue

            self.index_files(file_idx_writer, repo_name, repo)
            self.index_changesets(chgset_idx_writer, repo_name, repo)

        log.debug('>> COMMITING CHANGES <<')
        file_idx_writer.commit(merge=True)
        chgset_idx_writer.commit(merge=True)
        log.debug('>>> FINISHED BUILDING INDEX <<<')

    def update_indexes(self):
        self.update_file_index()
        self.update_changeset_index()

    def run(self, full_index=False):
        """Run daemon"""
        if full_index or self.initial:
            self.build_indexes()
        else:
            self.update_indexes()


@celerylib.task
@celerylib.locked_task
def whoosh_index(repo_location, full_index):
    index_location = config['index_dir']
    WhooshIndexingDaemon(index_location=index_location,
                         repo_location=repo_location) \
                         .run(full_index=full_index)
