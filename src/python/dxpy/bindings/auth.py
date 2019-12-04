# Copyright (C) 2013-2016 DNAnexus, Inc.
#
# This file is part of dx-toolkit (DNAnexus platform client libraries).
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may not
#   use this file except in compliance with the License. You may obtain a copy
#   of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

from __future__ import print_function, unicode_literals, division, absolute_import
from collections import defaultdict

from dxpy import get_auth_server_name, DXHTTPRequest
import functools

from dxpy.api import system_whoami


def _dx_http_request_to_auth_server(
    endpoint, data, authserver_host=None, authserver_port=None, **http_request_kwargs
):
    authserver = get_auth_server_name(authserver_host, authserver_port)
    http_request_kwargs["prepend_srv"] = False
    return DXHTTPRequest(authserver + endpoint, data, **http_request_kwargs)


def user_info(authserver_host=None, authserver_port=None):
    """Returns the result of the user_info call against the specified auth
    server.

    .. deprecated:: 0.108.0
       Use :func:`whoami` instead where possible.

    """
    return _dx_http_request_to_auth_server(
        "/system/getUserInfo",
        {},
        authserver_host=authserver_host,
        authserver_port=authserver_port,
    )


def whoami():
    """
    Returns the user ID of the currently requesting user.
    """
    return system_whoami()["id"]


def api_find_access_tokens(input_params, authserver_host=None, authserver_port=None):
    return _dx_http_request_to_auth_server(
        "/account/findAccessTokens", input_params,
        authserver_host=authserver_host, authserver_port=authserver_port)


def find_access_tokens(label=True, types=None, authserver_host=None,
                       authserver_port=None, first_page_size=100):
    """Returns a generator over all access tokens"""
    from dxpy.bindings.search import _find
    func = functools.partial(api_find_access_tokens, authserver_host=authserver_host,
                             authserver_port=authserver_port)
    query = {'label': label}
    if types:
        query['types'] = types
    return _find(func, query, None, None, first_page_size, max_result_set_size=100, result_key="tokens")






def list_auth_tokens(label=True, authserver_host=None, authserver_port=None):
    """List all auth tokens for current user - this is an undocumented API.

    :param label: If true, return human labels
    :type label: boolean

    Note that with label=False, not all auth tokens will be returned for some reason.
    """
    return _dx_http_request_to_auth_server(
        "/account/listAuthTokens",
        {"label": label},
        authserver_host=authserver_host,
        authserver_port=authserver_port,
    )


def destroy_auth_token(token_signature, authserver_host=None, authserver_port=None):
    """Delete and disable an auth token"""
    return _dx_http_request_to_auth_server(
        "/system/destroyAuthToken",
        {"tokenSignature": token_signature},
        authserver_host=authserver_host,
        authserver_port=authserver_port,
    )


def destroy_token_and_descendants(
    token_signature, authserver_host=None, authserver_port=None, dryrun=False
):
    api_resp = list_auth_tokens(
        authserver_host=authserver_host, authserver_port=authserver_port, label=True
    )
    tokens = api_resp["tokens"]
    sig2children = defaultdict(list)
    sig2token = defaultdict(dict)
    for token in tokens:
        sig2token[token["signature"]] = token
        parent_sig = token.get("parentSignature")
        if parent_sig:
            sig2children[parent_sig].append(token)
    signatures_to_destroy = [token_signature]
    print(sig2children)
    children = list(sig2children[token_signature])
    while children:
        curr = children.pop()
        sig = curr["signature"]
        children.extend(sig2children[sig])
        signatures_to_destroy.append(sig)
    for sig in signatures_to_destroy[::-1]:
        print(
            "Destroying {signature} ({label})".format(
                signature=sig, label=sig2token[sig].get("label")
            )
        )
        if not dryrun:
            destroy_auth_token(
                sig, authserver_host=authserver_host, authserver_port=authserver_port
            )


class ScopeBuilder(object):
    def __init__(self):
        self.projects = {}
        self.phiAccess = False

    def set_phi_access(self, phi_access):
        self.phiAccess = phi_access
        return self

    def set_all_projects_access(self, level):
        if level is None:
            self.projects.pop("*")
        else:
            self.projects["*"] = level
        return self

    def set_project_access(self, project_id, level):
        from dxpy.bindings import verify_string_dxid

        verify_string_dxid(project_id, ("project",))
        if level is None:
            self.projects.pop(project_id)
        else:
            self.projects[project_id] = level
        return self

    def compile(self):
        return {"projects": self.projects, "phiAccess": self.phiAccess}


def new_auth_token(scope, label, expires=None, authserver_host=None, authserver_port=None):
    """List all auth tokens for current user - this is an undocumented API.

    :param scope: access to be granted to token
    :type scope: dict
    :param label: If true, return human labels
    :type label: boolean
    :param expires: Expiration date or time for token (see normalize_time_input for more detail on
    valid inputs)
    :type expires: string or milliseconds since epic
    :returns: newly created API token
    :return type: dict

    Example return:
    {"token"

    Examples of scopes:

    * PHI access and contribute level to given project ID::
      ``{"projects":{"<project_ID>":"CONTRIBUTE"}, "phiAccess": true}``
    * All project CONTRIBUTE access, including PHI:
      ``{"projects":{"*":"CONTRIBUTE"}, "phiAccess": true}``
    * All project VIEW access, single project CONTRIBUTE:
      ``{"projects":{"*":"VIEW","<project ID>": "CONTRIBUTE"}}``
    """
    from dxpy.utils import normalize_time_input
    input_params = {"scope": scope}
    if label:
        input_params["label"] = label
    if expires:
        input_params["expires"] = normalize_time_input(expires)
    return _dx_http_request_to_auth_server(
        "/system/newAuthToken",
        input_params,
        authserver_host=authserver_host,
        authserver_port=authserver_port,
    )
