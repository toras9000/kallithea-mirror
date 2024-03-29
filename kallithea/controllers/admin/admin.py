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
kallithea.controllers.admin.admin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Controller for Admin panel of Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Apr 7, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""


import logging

from sqlalchemy.orm import joinedload
from sqlalchemy.sql.expression import and_, func, or_
from tg import request
from tg import tmpl_context as c
from whoosh import query
from whoosh.qparser.dateparse import DateParserPlugin
from whoosh.qparser.default import QueryParser

from kallithea.controllers import base
from kallithea.lib.auth import HasPermissionAnyDecorator, LoginRequired
from kallithea.lib.indexers import JOURNAL_SCHEMA
from kallithea.lib.page import Page
from kallithea.lib.utils2 import remove_prefix, remove_suffix, safe_int
from kallithea.model import db


log = logging.getLogger(__name__)


def _journal_filter(user_log, search_term):
    """
    Filters sqlalchemy user_log based on search_term with whoosh Query language
    http://packages.python.org/Whoosh/querylang.html

    :param user_log:
    :param search_term:
    """
    log.debug('Initial search term: %r', search_term)
    qry = None
    if search_term:
        qp = QueryParser('repository', schema=JOURNAL_SCHEMA)
        qp.add_plugin(DateParserPlugin())
        qry = qp.parse(search_term)
        log.debug('Filtering using parsed query %r', qry)

    def wildcard_handler(col, wc_term):
        if wc_term.startswith('*') and not wc_term.endswith('*'):
            # postfix == endswith
            wc_term = remove_prefix(wc_term, prefix='*')
            return func.lower(col).endswith(func.lower(wc_term))
        elif wc_term.startswith('*') and wc_term.endswith('*'):
            # wildcard == ilike
            wc_term = remove_prefix(wc_term, prefix='*')
            wc_term = remove_suffix(wc_term, suffix='*')
            return func.lower(col).contains(func.lower(wc_term))

    def get_filterion(field, val, term):

        if field == 'repository':
            field = getattr(db.UserLog, 'repository_name')
        elif field == 'ip':
            field = getattr(db.UserLog, 'user_ip')
        elif field == 'date':
            field = getattr(db.UserLog, 'action_date')
        elif field == 'username':
            field = getattr(db.UserLog, 'username')
        else:
            field = getattr(db.UserLog, field)
        log.debug('filter field: %s val=>%s', field, val)

        # sql filtering
        if isinstance(term, query.Wildcard):
            return wildcard_handler(field, val)
        elif isinstance(term, query.Prefix):
            return func.lower(field).startswith(func.lower(val))
        elif isinstance(term, query.DateRange):
            return and_(field >= val[0], field <= val[1])
        return func.lower(field) == func.lower(val)

    if isinstance(qry, (query.And, query.Term, query.Prefix, query.Wildcard,
                        query.DateRange)):
        if not isinstance(qry, query.And):
            qry = [qry]
        for term in qry:
            assert term is not None, term
            field = term.fieldname
            val = (term.text if not isinstance(term, query.DateRange)
                   else [term.startdate, term.enddate])
            user_log = user_log.filter(get_filterion(field, val, term))
    elif isinstance(qry, query.Or):
        filters = []
        for term in qry:
            field = term.fieldname
            val = (term.text if not isinstance(term, query.DateRange)
                   else [term.startdate, term.enddate])
            filters.append(get_filterion(field, val, term))
        user_log = user_log.filter(or_(*filters))

    return user_log


class AdminController(base.BaseController):

    @LoginRequired(allow_default_user=True)
    def _before(self, *args, **kwargs):
        super(AdminController, self)._before(*args, **kwargs)

    @HasPermissionAnyDecorator('hg.admin')
    def index(self):
        users_log = db.UserLog.query() \
                .options(joinedload(db.UserLog.user)) \
                .options(joinedload(db.UserLog.repository))

        # FILTERING
        c.search_term = request.GET.get('filter')
        users_log = _journal_filter(users_log, c.search_term)

        users_log = users_log.order_by(db.UserLog.action_date.desc())

        p = safe_int(request.GET.get('page'), 1)

        c.users_log = Page(users_log, page=p, items_per_page=10,
                           filter=c.search_term)

        if request.environ.get('HTTP_X_PARTIAL_XHR'):
            return base.render('admin/admin_log.html')

        return base.render('admin/admin.html')
