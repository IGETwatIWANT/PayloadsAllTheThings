"""Advanced web attack modules."""
from bas.modules.web.xxe import XXEModule
from bas.modules.web.deserialization import DeserializationModule
from bas.modules.web.open_redirect import OpenRedirectModule
from bas.modules.web.cors import CORSModule
from bas.modules.web.crlf import CRLFModule
from bas.modules.web.path_traversal import PathTraversalModule
from bas.modules.web.prototype_pollution import PrototypePollutionModule
from bas.modules.web.file_upload import FileUploadModule
from bas.modules.web.idor import IDORModule
from bas.modules.web.csrf import CSRFModule
from bas.modules.web.cache_deception import CacheDeceptionModule
from bas.modules.web.request_smuggling import RequestSmugglingModule
from bas.modules.web.graphql import GraphQLModule
from bas.modules.web.websocket import WebSocketModule
from bas.modules.web.nosqli import NoSQLiModule
from bas.modules.web.ldap import LDAPiModule
from bas.modules.web.xpath import XPathiModule
from bas.modules.web.hpp import HPPModule

__all__ = [
    "XXEModule", "DeserializationModule", "OpenRedirectModule", "CORSModule",
    "CRLFModule", "PathTraversalModule", "PrototypePollutionModule", "FileUploadModule",
    "IDORModule", "CSRFModule", "CacheDeceptionModule", "RequestSmugglingModule",
    "GraphQLModule", "WebSocketModule", "NoSQLiModule", "LDAPiModule",
    "XPathiModule", "HPPModule",
]
