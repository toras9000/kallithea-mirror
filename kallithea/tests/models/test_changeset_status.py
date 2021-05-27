from kallithea.model import db
from kallithea.model.changeset_status import ChangesetStatusModel
from kallithea.tests import base


STATUS_UNDER_REVIEW = db.ChangesetStatus.STATUS_UNDER_REVIEW
STATUS_APPROVED = db.ChangesetStatus.STATUS_APPROVED
STATUS_REJECTED = db.ChangesetStatus.STATUS_REJECTED
STATUS_NOT_REVIEWED = db.ChangesetStatus.STATUS_NOT_REVIEWED


class CSM(object): # ChangesetStatusMock

    def __init__(self, status):
        self.status = status


class TestChangesetStatusCalculation(base.TestController):

    def setup_method(self, method):
        self.m = ChangesetStatusModel()

    @base.parametrize('name,expected_result,statuses', [
        ('empty list', STATUS_UNDER_REVIEW, []),
        ('approve', STATUS_APPROVED, [CSM(STATUS_APPROVED)]),
        ('approve2', STATUS_APPROVED, [CSM(STATUS_APPROVED), CSM(STATUS_APPROVED)]),
        ('approve_reject', STATUS_REJECTED, [CSM(STATUS_APPROVED), CSM(STATUS_REJECTED)]),
        ('approve_underreview', STATUS_UNDER_REVIEW, [CSM(STATUS_APPROVED), CSM(STATUS_UNDER_REVIEW)]),
        ('approve_notreviewed', STATUS_UNDER_REVIEW, [CSM(STATUS_APPROVED), CSM(STATUS_NOT_REVIEWED)]),
        ('underreview', STATUS_UNDER_REVIEW, [CSM(STATUS_UNDER_REVIEW), CSM(STATUS_UNDER_REVIEW)]),
        ('reject', STATUS_REJECTED, [CSM(STATUS_REJECTED)]),
        ('reject_underreview', STATUS_REJECTED, [CSM(STATUS_REJECTED), CSM(STATUS_UNDER_REVIEW)]),
        ('reject_notreviewed', STATUS_REJECTED, [CSM(STATUS_REJECTED), CSM(STATUS_NOT_REVIEWED)]),
        ('notreviewed', STATUS_UNDER_REVIEW, [CSM(STATUS_NOT_REVIEWED)]),
        ('approve_none', STATUS_UNDER_REVIEW, [CSM(STATUS_APPROVED), None]),
        ('approve2_none', STATUS_UNDER_REVIEW, [CSM(STATUS_APPROVED), CSM(STATUS_APPROVED), None]),
        ('approve_reject_none', STATUS_REJECTED, [CSM(STATUS_APPROVED), CSM(STATUS_REJECTED), None]),
        ('approve_underreview_none', STATUS_UNDER_REVIEW, [CSM(STATUS_APPROVED), CSM(STATUS_UNDER_REVIEW), None]),
        ('approve_notreviewed_none', STATUS_UNDER_REVIEW, [CSM(STATUS_APPROVED), CSM(STATUS_NOT_REVIEWED), None]),
        ('underreview_none', STATUS_UNDER_REVIEW, [CSM(STATUS_UNDER_REVIEW), CSM(STATUS_UNDER_REVIEW), None]),
        ('reject_none', STATUS_REJECTED, [CSM(STATUS_REJECTED), None]),
        ('reject_underreview_none', STATUS_REJECTED, [CSM(STATUS_REJECTED), CSM(STATUS_UNDER_REVIEW), None]),
        ('reject_notreviewed_none', STATUS_REJECTED, [CSM(STATUS_REJECTED), CSM(STATUS_NOT_REVIEWED), None]),
        ('notreviewed_none', STATUS_UNDER_REVIEW, [CSM(STATUS_NOT_REVIEWED), None]),
    ])
    def test_result(self, name, expected_result, statuses):
        result = self.m._calculate_status(statuses)
        assert result == expected_result
