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

"""add unique constraint on PullRequestReviewer

Revision ID: f62826179f39
Revises: a0a1bf09c143
Create Date: 2020-06-15 12:30:37.420321

"""

# The following opaque hexadecimal identifiers ("revisions") are used
# by Alembic to track this migration script and its relations to others.
revision = 'f62826179f39'
down_revision = 'a0a1bf09c143'
branch_labels = None
depends_on = None

import sqlalchemy as sa
from alembic import op

from kallithea.model import db


def upgrade():
    session = sa.orm.session.Session(bind=op.get_bind())

    # there may be existing duplicates in the database, remove them first

    seen = set()
    # duplicate_values contains one copy of each duplicated pair
    duplicate_values = (
        session
        .query(db.PullRequestReviewer.pull_request_id, db.PullRequestReviewer.user_id)
        .group_by(db.PullRequestReviewer.pull_request_id, db.PullRequestReviewer.user_id)
        .having(sa.func.count(db.PullRequestReviewer.pull_request_reviewers_id) > 1)
    )

    for pull_request_id, user_id in duplicate_values:
        # duplicate_occurrences contains all db records of the duplicate_value
        # currently being processed
        duplicate_occurrences = (
            session
            .query(db.PullRequestReviewer)
            .filter(db.PullRequestReviewer.pull_request_id == pull_request_id)
            .filter(db.PullRequestReviewer.user_id == user_id)
        )
        for prr in duplicate_occurrences:
            if (pull_request_id, user_id) in seen:
                session.delete(prr)
            else:
                seen.add((pull_request_id, user_id))

    session.commit()

    # after deleting all duplicates, add the unique constraint
    with op.batch_alter_table('pull_request_reviewers', schema=None) as batch_op:
        batch_op.create_unique_constraint(batch_op.f('uq_pull_request_reviewers_pull_request_id'), ['pull_request_id', 'user_id'])


def downgrade():
    with op.batch_alter_table('pull_request_reviewers', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('uq_pull_request_reviewers_pull_request_id'), type_='unique')
