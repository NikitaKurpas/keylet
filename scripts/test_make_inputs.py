"""Harmless Make expansion regression; never executes the signing target/helper."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

class MakeInputTests(unittest.TestCase):
    def test_literal_command_line_inputs(self):
        root=Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)
            marker=directory/'unexpected-expression-expansion'
            expression='$(shell touch '+str(marker)+')'
            values={'PROFILE':str(directory/'profile with spaces ')+expression+'.provisionprofile',
                'IDENTITY':expression, 'TEAM_ID':expression, 'SIGNING_MODE':expression, 'SIGNING_KEYCHAIN':expression}
            fixture=directory/'fixture.mk'
            fixture.write_text('include '+str(root/'Makefile')+'\n.PHONY: capture\ncapture:\n\tpython3 -c \'import os,json; print(json.dumps({k:os.environ[k] for k in ["PROFILE","IDENTITY","TEAM_ID","SIGNING_MODE","SIGNING_KEYCHAIN"]}))\'\n')
            result=subprocess.run(['/usr/bin/make','--no-print-directory','-s','-f',str(fixture),'capture',*[key+'='+value for key,value in values.items()]],
                cwd=directory,text=True,capture_output=True,check=True)
            import json
            self.assertEqual(json.loads(result.stdout),values)
            self.assertFalse(marker.exists(),'Make evaluated a literal input expression')

    def test_literal_environment_inputs(self):
        root=Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)
            marker=directory/'unexpected-expression-expansion'
            values={key:'$(shell touch '+str(marker)+')' for key in ['PROFILE','IDENTITY','TEAM_ID','SIGNING_MODE','SIGNING_KEYCHAIN']}
            fixture=directory/'fixture.mk'
            fixture.write_text('include '+str(root/'Makefile')+'\n.PHONY: capture\ncapture:\n\tpython3 -c \'import os,json; print(json.dumps({k:os.environ[k] for k in ["PROFILE","IDENTITY","TEAM_ID","SIGNING_MODE","SIGNING_KEYCHAIN"]}))\'\n')
            result=subprocess.run(['/usr/bin/make','--no-print-directory','-s','-f',str(fixture),'capture'],
                cwd=directory,env={**os.environ,**values},text=True,capture_output=True,check=True)
            import json
            self.assertEqual(json.loads(result.stdout),values)
            self.assertFalse(marker.exists(),'Make evaluated a literal environment expression')

if __name__=='__main__': unittest.main()
