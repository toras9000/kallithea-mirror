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
kallithea.model.gist
~~~~~~~~~~~~~~~~~~~~

gist model for Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: May 9, 2013
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import logging
import os
import random
import shutil
import time
import traceback

from kallithea.lib import ext_json
from kallithea.lib.utils2 import AttributeDict, ascii_bytes, safe_int, time_to_datetime
from kallithea.model import db, meta, repo, scm


log = logging.getLogger(__name__)


def make_gist_access_id():
    """Generate a random, URL safe, almost certainly unique gist identifier."""
    rnd = random.SystemRandom() # use cryptographically secure system PRNG
    alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjklmnpqrstuvwxyz'
    length = 20
    return ''.join(rnd.choice(alphabet) for _ in range(length))


class GistModel(object):

    def __delete_gist(self, gist):
        """
        removes gist from filesystem

        :param gist: gist object
        """
        root_path = repo.RepoModel().repos_path
        rm_path = os.path.join(root_path, db.Gist.GIST_STORE_LOC, gist.gist_access_id)
        log.info("Removing %s", rm_path)
        shutil.rmtree(rm_path)

    def _store_metadata(self, fs_repo, gist_id, gist_access_id, user_id, gist_type,
                        gist_expires):
        """
        store metadata inside the gist, this can be later used for imports
        or gist identification
        """
        metadata = {
            'metadata_version': '1',
            'gist_db_id': gist_id,
            'gist_access_id': gist_access_id,
            'gist_owner_id': user_id,
            'gist_type': gist_type,
            'gist_expires': gist_expires,
            'gist_updated': time.time(),
        }
        with open(os.path.join(fs_repo.path, '.hg', db.Gist.GIST_METADATA_FILE), 'wb') as f:
            f.write(ascii_bytes(ext_json.dumps(metadata)))

    def get_gist(self, gist):
        return db.Gist.guess_instance(gist)

    def get_gist_files(self, gist_access_id, revision=None):
        """
        Get files for given gist

        :param gist_access_id:
        """
        gist_repo = db.Gist.get_by_access_id(gist_access_id)
        cs = gist_repo.scm_instance.get_changeset(revision)
        return cs, [n for n in cs.get_node('/')]

    def create(self, description, owner, ip_addr, gist_mapping,
               gist_type=db.Gist.GIST_PUBLIC, lifetime=-1):
        """

        :param description: description of the gist
        :param owner: user who created this gist
        :param gist_mapping: mapping {filename:{'content':content},...}
        :param gist_type: type of gist private/public
        :param lifetime: in minutes, -1 == forever
        """
        owner = db.User.guess_instance(owner)
        gist_access_id = make_gist_access_id()
        lifetime = safe_int(lifetime, -1)
        gist_expires = time.time() + (lifetime * 60) if lifetime != -1 else -1
        log.debug('set GIST expiration date to: %s',
                  time_to_datetime(gist_expires)
                   if gist_expires != -1 else 'forever')
        # create the Database version
        gist = db.Gist()
        gist.gist_description = description
        gist.gist_access_id = gist_access_id
        gist.owner_id = owner.user_id
        gist.gist_expires = gist_expires
        gist.gist_type = gist_type
        meta.Session().add(gist)
        meta.Session().flush() # make database assign gist.gist_id
        if gist_type == db.Gist.GIST_PUBLIC:
            # use DB ID for easy to use GIST ID
            gist.gist_access_id = str(gist.gist_id)

        log.debug('Creating new %s GIST repo %s', gist_type, gist.gist_access_id)
        fs_repo = repo.RepoModel()._create_filesystem_repo(
            repo_name=gist.gist_access_id, repo_type='hg', repo_group=db.Gist.GIST_STORE_LOC)

        processed_mapping = {}
        for filename in gist_mapping:
            if filename != os.path.basename(filename):
                raise Exception('Filename cannot be inside a directory')

            content = gist_mapping[filename]['content']
            # TODO: expand support for setting explicit lexers
#             if lexer is None:
#                 try:
#                     guess_lexer = pygments.lexers.guess_lexer_for_filename
#                     lexer = guess_lexer(filename,content)
#                 except pygments.util.ClassNotFound:
#                     lexer = 'text'
            processed_mapping[filename] = {'content': content}

        # now create single multifile commit
        message = 'added file'
        message += 's: ' if len(processed_mapping) > 1 else ': '
        message += ', '.join([x for x in processed_mapping])

        # fake Kallithea Repository object
        fake_repo = AttributeDict(dict(
            repo_name=os.path.join(db.Gist.GIST_STORE_LOC, gist.gist_access_id),
            scm_instance_no_cache=lambda: fs_repo,
        ))
        scm.ScmModel().create_nodes(
            user=owner.user_id,
            ip_addr=ip_addr,
            repo=fake_repo,
            message=message,
            nodes=processed_mapping,
            trigger_push_hook=False
        )

        self._store_metadata(fs_repo, gist.gist_id, gist.gist_access_id,
                             owner.user_id, gist.gist_type, gist.gist_expires)
        return gist

    def delete(self, gist, fs_remove=True):
        gist = db.Gist.guess_instance(gist)
        try:
            meta.Session().delete(gist)
            if fs_remove:
                self.__delete_gist(gist)
            else:
                log.debug('skipping removal from filesystem')
        except Exception:
            log.error(traceback.format_exc())
            raise

    def update(self, gist, description, owner, ip_addr, gist_mapping, gist_type,
               lifetime):
        gist = db.Gist.guess_instance(gist)
        gist_repo = gist.scm_instance

        lifetime = safe_int(lifetime, -1)
        if lifetime == 0:  # preserve old value
            gist_expires = gist.gist_expires
        else:
            gist_expires = time.time() + (lifetime * 60) if lifetime != -1 else -1

        # calculate operation type based on given data
        gist_mapping_op = {}
        for k, v in gist_mapping.items():
            # add, mod, del
            if not v['org_filename'] and v['filename']:
                op = 'add'
            elif v['org_filename'] and not v['filename']:
                op = 'del'
            else:
                op = 'mod'

            v['op'] = op
            gist_mapping_op[k] = v

        gist.gist_description = description
        gist.gist_expires = gist_expires
        gist.owner = owner
        gist.gist_type = gist_type

        message = 'updated file'
        message += 's: ' if len(gist_mapping) > 1 else ': '
        message += ', '.join([x for x in gist_mapping])

        # fake Kallithea Repository object
        fake_repo = AttributeDict(dict(
            repo_name=os.path.join(db.Gist.GIST_STORE_LOC, gist.gist_access_id),
            scm_instance_no_cache=lambda: gist_repo,
        ))

        self._store_metadata(gist_repo, gist.gist_id, gist.gist_access_id,
                             owner.user_id, gist.gist_type, gist.gist_expires)

        scm.ScmModel().update_nodes(
            user=owner.user_id,
            ip_addr=ip_addr,
            repo=fake_repo,
            message=message,
            nodes=gist_mapping_op,
            trigger_push_hook=False
        )

        return gist
