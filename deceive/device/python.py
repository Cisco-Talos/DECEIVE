"""A small virtual Python console. Parsed syntax never reaches Python execution."""
from __future__ import annotations

import ast
import operator
import posixpath

from deceive.interaction import Response, Session
from deceive.models import Profile

VERSION = 'Python 3.7.3'
BANNER = (VERSION + ' (default, Oct 18 2019, 09:00:00) [GCC 8.3.0] on linux\n'
          'Type "help", "copyright", "credits" or "license" for more information.\n')


class VirtualPythonError(Exception):
    pass


class UnsupportedVirtualPython(VirtualPythonError):
    pass


def _evaluate(node: ast.expr, profile: Profile, session: Session,
              imports: list[str], depth: int = 0) -> object:
    from deceive.device.engine import file_view, path, permitted

    if depth > 12:
        raise VirtualPythonError('RecursionError: maximum recursion depth exceeded')
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float, bool, type(None))):
        if isinstance(node.value, str) and len(node.value.encode()) > 4096:
            raise VirtualPythonError('ValueError: string exceeds virtual limit')
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
        left = _evaluate(node.left, profile, session, imports, depth + 1)
        right = _evaluate(node.right, profile, session, imports, depth + 1)
        if type(left) not in {int, float} or type(right) not in {int, float}:
            raise VirtualPythonError('TypeError: unsupported operand type')
        result = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul}[
            type(node.op)](left, right)
        if abs(result) > 10**12:
            raise VirtualPythonError('OverflowError: virtual numeric limit exceeded')
        return result
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _evaluate(node.operand, profile, session, imports, depth + 1)
        if type(value) not in {int, float}:
            raise VirtualPythonError('TypeError: bad operand type')
        return value if isinstance(node.op, ast.UAdd) else -value
    if isinstance(node, ast.Call) and not node.keywords:
        if isinstance(node.func, ast.Name) and node.func.id in {
                'eval', 'exec', 'compile', '__import__', 'input'}:
            raise VirtualPythonError('PermissionError: operation unavailable')
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module = node.func.value.id
            if module == 'os' and node.func.attr in {
                    'system', 'popen', 'fork', 'execv', 'execve', 'spawnv'}:
                raise VirtualPythonError('PermissionError: operation unavailable')
            if module not in imports:
                raise VirtualPythonError(f"NameError: name '{module}' is not defined")
            if module == 'os' and node.func.attr == 'getcwd' and not node.args:
                from deceive.device.engine import home
                return session.state.get('cwd', home(profile, session))
            if module == 'os' and node.func.attr == 'listdir' and len(node.args) <= 1:
                name = (_evaluate(node.args[0], profile, session, imports, depth + 1)
                        if node.args else '.')
                if not isinstance(name, str):
                    raise VirtualPythonError('TypeError: path should be string')
                key = path(profile, session, name)
                files, directories = file_view(profile, session)
                if key not in directories:
                    raise VirtualPythonError(f"FileNotFoundError: [Errno 2] No such file or directory: {name!r}")
                return sorted(posixpath.basename(item) for item in files.keys() | directories
                              if item != key and posixpath.dirname(item) == key)
        if (isinstance(node.func, ast.Attribute) and node.func.attr == 'read' and
                isinstance(node.func.value, ast.Call) and
                isinstance(node.func.value.func, ast.Name) and
                node.func.value.func.id == 'open' and
                len(node.func.value.args) == 1 and not node.func.value.keywords and
                not node.args):
            name = _evaluate(node.func.value.args[0], profile, session, imports, depth + 1)
            if not isinstance(name, str):
                raise VirtualPythonError('TypeError: path should be string')
            key = path(profile, session, name)
            files, _ = file_view(profile, session)
            if key not in files:
                raise VirtualPythonError(f"FileNotFoundError: [Errno 2] No such file or directory: {name!r}")
            if not permitted(profile, session, key, 'read'):
                raise VirtualPythonError(f"PermissionError: [Errno 13] Permission denied: {name!r}")
            return files[key].decode('utf-8', 'replace')
    if isinstance(node, ast.Name):
        raise VirtualPythonError(f"NameError: name '{node.id}' is not defined")
    raise UnsupportedVirtualPython('SyntaxError: unsupported virtual Python expression')


def run(profile: Profile, session: Session, source: str, imports: list[str],
        *, allow_model: bool = False) -> Response | None:
    if len(source.encode()) > 4096:
        return Response(stderr=b'ValueError: virtual Python input limit exceeded\n', exit_status=1)
    try:
        tree = ast.parse(source)
        if len(list(ast.walk(tree))) > 64 or len(tree.body) > 1:
            raise VirtualPythonError('SyntaxError: unsupported virtual Python statement')
        if not tree.body:
            return Response()
        statement = tree.body[0]
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name not in {'os', 'sys'} or alias.asname:
                    raise VirtualPythonError(f"ImportError: No module named '{alias.name}'")
                if alias.name not in imports:
                    imports.append(alias.name)
            return Response()
        if isinstance(statement, ast.Expr):
            expression = statement.value
            if (isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name)
                    and expression.func.id == 'print' and not expression.keywords):
                values = [_evaluate(arg, profile, session, imports) for arg in expression.args]
                return Response(body=(' '.join(map(str, values)) + '\n').encode())
            value = _evaluate(expression, profile, session, imports)
            return Response(body=(repr(value) + '\n').encode() if value is not None else b'')
        raise UnsupportedVirtualPython('SyntaxError: unsupported virtual Python statement')
    except SyntaxError:
        return Response(stderr=b'SyntaxError: invalid syntax\n', exit_status=1)
    except UnsupportedVirtualPython as exc:
        if allow_model:
            return None
        return Response(stderr=(str(exc) + '\n').encode(), exit_status=1)
    except VirtualPythonError as exc:
        return Response(stderr=(str(exc) + '\n').encode(), exit_status=1)
