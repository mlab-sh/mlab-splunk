#!/usr/bin/env python
# | mlab type=hash|url|ip|cve [field=<name>]  -> mlab_* fields from mlab.sh

import sys

import mlabsh
from splunklib.searchcommands import Configuration, Option, StreamingCommand, dispatch, validators


@Configuration(distributed=False)  # search head only: indexers often have no internet access
class MlabCommand(StreamingCommand):
    type = Option(require=True, validate=validators.Set(*mlabsh.FIELDS))
    field = Option(validate=validators.Fieldname())

    def stream(self, records):
        info = self.metadata.searchinfo
        try:
            key = mlabsh.secret(info.splunkd_uri, info.session_key, 'api_key')
        except Exception as e:  # e.g. user without list_storage_passwords: anonymous quotas
            self.write_warning(f'mlab: API key not readable ({e}), using anonymous lookups')
            key = None
        cache = mlabsh.Cache(mlabsh.cache_path())
        try:
            yield from mlabsh.enrich(records, self.type, self.field or mlabsh.FIELDS[self.type], key, cache,
                                     warn=self.write_warning)
        finally:
            cache.close()


dispatch(MlabCommand, sys.argv, sys.stdin, sys.stdout, __name__)
