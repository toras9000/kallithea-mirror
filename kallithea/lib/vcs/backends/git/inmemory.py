import datetime
import posixpath
import stat
import time

from dulwich import objects

from kallithea.lib.vcs.backends.base import BaseInMemoryChangeset
from kallithea.lib.vcs.exceptions import RepositoryError
from kallithea.lib.vcs.utils import ascii_str, safe_bytes

from . import repository


class GitInMemoryChangeset(BaseInMemoryChangeset):

    def commit(self, message, author, parents=None, branch=None, date=None,
               **kwargs):
        """
        Performs in-memory commit (doesn't check workdir in any way) and
        returns newly created ``Changeset``. Updates repository's
        ``revisions``.

        :param message: message of the commit
        :param author: full username, i.e. "Joe Doe <joe.doe@example.com>"
        :param parents: single parent or sequence of parents from which commit
          would be derived
        :param date: ``datetime.datetime`` instance. Defaults to
          ``datetime.datetime.now()``.
        :param branch: branch name, as string. If none given, default backend's
          branch would be used.

        :raises ``CommitError``: if any error occurs while committing
        """
        self.check_integrity(parents)

        if branch is None:
            branch = repository.GitRepository.DEFAULT_BRANCH_NAME

        repo = self.repository._repo
        object_store = repo.object_store

        ENCODING = b"UTF-8"  # TODO: should probably be kept in sync with safe_str/safe_bytes and vcs/conf/settings.py DEFAULT_ENCODINGS

        # Create tree and populates it with blobs
        commit_tree = self.parents[0] and repo[self.parents[0]._commit.tree] or \
            objects.Tree()
        for node in self.added + self.changed:
            # Compute subdirs if needed
            dirpath, nodename = posixpath.split(node.path)
            dirnames = safe_bytes(dirpath).split(b'/') if dirpath else []
            parent = commit_tree
            ancestors = [('', parent)]

            # Tries to dig for the deepest existing tree
            while dirnames:
                curdir = dirnames.pop(0)
                try:
                    dir_id = parent[curdir][1]
                except KeyError:
                    # put curdir back into dirnames and stops
                    dirnames.insert(0, curdir)
                    break
                else:
                    # If found, updates parent
                    parent = self.repository._repo[dir_id]
                    ancestors.append((curdir, parent))
            # Now parent is deepest existing tree and we need to create subtrees
            # for dirnames (in reverse order) [this only applies for nodes from added]
            new_trees = []

            blob = objects.Blob.from_string(node.content)

            node_path = safe_bytes(node.name)
            if dirnames:
                # If there are trees which should be created we need to build
                # them now (in reverse order)
                reversed_dirnames = list(reversed(dirnames))
                curtree = objects.Tree()
                curtree[node_path] = node.mode, blob.id
                new_trees.append(curtree)
                for dirname in reversed_dirnames[:-1]:
                    newtree = objects.Tree()
                    #newtree.add(stat.S_IFDIR, dirname, curtree.id)
                    newtree[dirname] = stat.S_IFDIR, curtree.id
                    new_trees.append(newtree)
                    curtree = newtree
                parent[reversed_dirnames[-1]] = stat.S_IFDIR, curtree.id
            else:
                parent.add(name=node_path, mode=node.mode, hexsha=blob.id)

            new_trees.append(parent)
            # Update ancestors
            for parent, tree, path in reversed([(a[1], b[1], b[0]) for a, b in
                zip(ancestors, ancestors[1:])]
            ):
                parent[path] = stat.S_IFDIR, tree.id
                object_store.add_object(tree)

            object_store.add_object(blob)
            for tree in new_trees:
                object_store.add_object(tree)
        for node in self.removed:
            paths = safe_bytes(node.path).split(b'/')
            tree = commit_tree
            trees = [tree]
            # Traverse deep into the forest...
            for path in paths:
                try:
                    obj = self.repository._repo[tree[path][1]]
                    if isinstance(obj, objects.Tree):
                        trees.append(obj)
                        tree = obj
                except KeyError:
                    break
            # Cut down the blob and all rotten trees on the way back...
            for path, tree in reversed(list(zip(paths, trees))):
                del tree[path]
                if tree:
                    # This tree still has elements - don't remove it or any
                    # of it's parents
                    break

        object_store.add_object(commit_tree)

        # Create commit
        commit = objects.Commit()
        commit.tree = commit_tree.id
        commit.parents = [p._commit.id for p in self.parents if p]
        commit.author = commit.committer = safe_bytes(author)
        commit.encoding = ENCODING
        commit.message = safe_bytes(message)

        # Compute date
        if date is None:
            date = time.time()
        elif isinstance(date, datetime.datetime):
            date = time.mktime(date.timetuple())

        author_time = kwargs.pop('author_time', date)
        commit.commit_time = int(date)
        commit.author_time = int(author_time)
        tz = time.timezone
        author_tz = kwargs.pop('author_timezone', tz)
        commit.commit_timezone = tz
        commit.author_timezone = author_tz

        object_store.add_object(commit)

        # Update vcs repository object & recreate dulwich repo
        ref = b'refs/heads/%s' % safe_bytes(branch)
        repo.refs[ref] = commit.id
        self.repository.revisions.append(ascii_str(commit.id))
        # invalidate parsed refs after commit
        self.repository._parsed_refs = self.repository._get_parsed_refs()
        tip = self.repository.get_changeset()
        self.reset()
        return tip

    def _get_missing_trees(self, path, root_tree):
        """
        Creates missing ``Tree`` objects for the given path.

        :param path: path given as a string. It may be a path to a file node
          (i.e. ``foo/bar/baz.txt``) or directory path - in that case it must
          end with slash (i.e. ``foo/bar/``).
        :param root_tree: ``dulwich.objects.Tree`` object from which we start
          traversing (should be commit's root tree)
        """
        dirpath = posixpath.split(path)[0]
        dirs = dirpath.split('/')
        if not dirs or dirs == ['']:
            return []

        def get_tree_for_dir(tree, dirname):
            for name, mode, id in tree.items():
                if name == dirname:
                    obj = self.repository._repo[id]
                    if isinstance(obj, objects.Tree):
                        return obj
                    else:
                        raise RepositoryError("Cannot create directory %s "
                            "at tree %s as path is occupied and is not a "
                            "Tree" % (dirname, tree))
            return None

        trees = []
        parent = root_tree
        for dirname in dirs:
            tree = get_tree_for_dir(parent, dirname)
            if tree is None:
                tree = objects.Tree()
                parent.add(stat.S_IFDIR, dirname, tree.id)
                parent = tree
            # Always append tree
            trees.append(tree)
        return trees
