#!/usr/bin/python
# -*- coding: utf-8 -*-
import logging
from pylons_app.lib.base import BaseController
from pylons import c, g, session, h, request
from mako.template import Template
from pprint import pprint
import os
#uncomment the following if you want to serve a single repo
#from mercurial.hgweb.hgweb_mod import hgweb
from mercurial.hgweb.hgwebdir_mod import hgwebdir
from mercurial.hgweb.request import wsgiapplication
log = logging.getLogger(__name__)

from mercurial import ui, hg
from mercurial.error import RepoError
from ConfigParser import ConfigParser
#http://bel-epa.com/hg/
#def make_web_app():
#    repos = "hgwebdir.config"
#    hgwebapp = hgwebdir(repos)
#    return hgwebapp
#
#class HgController(BaseController):
#
#    def index(self):
#        hgapp = wsgiapplication(make_web_app)
#        return hgapp(request.environ, self.start_response)
#
#    def view(self, *args, **kwargs):
#        return u'dupa'
#        #pprint(request.environ)
#        hgapp = wsgiapplication(make_web_app)
#        return hgapp(request.environ, self.start_response)

def _make_app():
    #for single a repo
    #return hgweb("/path/to/repo", "Name")
    repos = "hgwebdir.config"
    return  hgwebdir(repos)

def wsgi_app(environ, start_response):
    start_response('200 OK', [('Content-type', 'text/html')])
    return ['<html>\n<body>\nHello World!\n</body>\n</html>']

class HgController(BaseController):

    def _check_repo(self, repo_name):

        p = os.path.dirname(__file__)
        config_path = os.path.join(p, '../..', 'hgwebdir.config')
        print config_path

        cp = ConfigParser()

        cp.read(config_path)
        repos_path = cp.get('paths', '/').replace("**", '')

        if not repos_path:
            raise Exception('Could not read config !')

        self.repo_path = os.path.join(repos_path, repo_name)

        try:
            r = hg.repository(ui.ui(), self.repo_path)
            hg.verify(r)
            #here we hnow that repo exists it was verified
            log.info('%s repo is already created', repo_name)
            raise Exception('Repo exists')
        except RepoError:
            log.info('%s repo is free for creation', repo_name)
            #it means that there is no valid repo there...
            return True


    def _create_repo(self, repo_name):
        if repo_name in [None, '', 'add']:
            raise Exception('undefined repo_name of repo')

        if self._check_repo(repo_name):
            log.info('creating repo %s in %s', repo_name, self.repo_path)
            cmd = """mkdir %s && hg init %s""" \
                    % (self.repo_path, self.repo_path)
            os.popen(cmd)


    def add_repo(self, new_repo):
        tmpl = '''
                  <html>
                    <body>
                        %(msg)s%(new_repo)s!<br \>
                        <a href="/">repos</a>
                    </body>
                  </html>
                '''
        #extra check it can be add since it's the command
        if new_repo == 'add':
            return [tmpl % ({'new_repo':'', 'msg':'you basstard ! this repo is a command'})]

        new_repo = new_repo.replace(" ", "_")
        new_repo = new_repo.replace("-", "_")

        try:
            self._create_repo(new_repo)
        except Exception as e:
            return [tmpl % ({'new_repo':' Exception when adding: ' + new_repo, 'msg':str(e)})]

        return [tmpl % ({'new_repo':new_repo, 'msg':'added repo: '})]

    def view(self, environ, start_response):
        #the following is only needed when using hgwebdir
        app = _make_app()
        #return wsgi_app(environ, start_response)
        response = app(request.environ, self.start_response)

        if environ['PATH_INFO'].find("static") != -1:
            return response
        else:
            #wrap the murcurial response in a mako template.
            template = Template("".join(response),
                                lookup = environ['pylons.pylons']\
                                .config['pylons.g'].mako_lookup)

            return template.render(g = g, c = c, session = session, h = h)

