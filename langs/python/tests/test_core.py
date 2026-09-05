import unittest
from ores_lib_core import DIRECTORY_ADMIN_ROLE, DIRECTORY_REVOCATIONS_EXECUTE_SCOPE, REDACTED, DirectoryGrant, Secret, authorized_directory_organizations, redact_record, valid_correlation_id
class CoreTests(unittest.TestCase):
    def test_redaction(self): self.assertEqual(redact_record({"access_token":"x","ok":"y"}), {"access_token":REDACTED,"ok":"y"})
    def test_secret(self): self.assertEqual(str(Secret("x")), REDACTED)
    def test_correlation(self): self.assertTrue(valid_correlation_id("req-12345678")); self.assertFalse(valid_correlation_id("bad space"))
    def test_directory_grant(self):
        grant=DirectoryGrant("20000000-0000-4000-8000-000000000001","10000000-0000-4000-8000-000000000001",None,(DIRECTORY_REVOCATIONS_EXECUTE_SCOPE,),(DIRECTORY_ADMIN_ROLE,),"2026-08-11T21:00:00Z",None)
        self.assertEqual(authorized_directory_organizations(None,DIRECTORY_REVOCATIONS_EXECUTE_SCOPE,(grant,)),(grant.organization_id,))
        self.assertEqual(authorized_directory_organizations(None,"directory.*",(grant,)),())
        project_grant=DirectoryGrant(grant.grant_id,grant.organization_id,("30000000-0000-4000-8000-000000000001",),grant.scopes,grant.roles,grant.granted_at,grant.expires_at)
        self.assertEqual(authorized_directory_organizations(None,DIRECTORY_REVOCATIONS_EXECUTE_SCOPE,(project_grant,)),())
if __name__ == "__main__": unittest.main()
