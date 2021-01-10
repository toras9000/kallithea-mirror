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

"""hooks: migrate internal hooks to kallithea namespace

Revision ID: 7ba0d2cad930
Revises: f62826179f39
Create Date: 2021-01-11 00:10:13.576586

"""

# The following opaque hexadecimal identifiers ("revisions") are used
# by Alembic to track this migration script and its relations to others.
revision = '7ba0d2cad930'
down_revision = 'f62826179f39'
branch_labels = None
depends_on = None

from alembic import op
from sqlalchemy import MetaData, Table

from kallithea.model import db


meta = MetaData()


def upgrade():
    meta.bind = op.get_bind()
    ui = Table(db.Ui.__tablename__, meta, autoload=True)

    ui.update(values={
        'ui_key': 'changegroup.kallithea_update',
        'ui_value': 'python:',  # value in db isn't used
    }).where(ui.c.ui_key == 'changegroup.update').execute()
    ui.update(values={
        'ui_key': 'changegroup.kallithea_repo_size',
        'ui_value': 'python:',  # value in db isn't used
    }).where(ui.c.ui_key == 'changegroup.repo_size').execute()

    # 642847355a10 moved these hooks out of db - remove old entries
    ui.delete().where(ui.c.ui_key == 'changegroup.push_logger').execute()
    ui.delete().where(ui.c.ui_key == 'outgoing.pull_logger').execute()


def downgrade():
    pass
