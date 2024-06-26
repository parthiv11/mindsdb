import unittest
from mindsdb.api.executor.data_types.response_type import RESPONSE_TYPE
from mindsdb.integrations.handlers.datastax_handler.datastax_handler import (
    DatastaxHandler,
)


class DatastaxHandlerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kwargs = {
            "connection_data": {
                "user": "cassandra",
                "password": "",
                "secure_connect_bundle": "/home/Downloads/file.zip",
            }
        }
        cls.handler = DatastaxHandler("test_datastax_handler", **cls.kwargs)

    def test_0_connect(self):
        self.handler.check_connection()

    def test_1_native_query_show_keyspaces(self):
        dbs = self.handler.native_query("DESC KEYSPACES;")
        assert dbs.type is not RESPONSE_TYPE.ERROR

    def test_2_get_tables(self):
        tbls = self.handler.get_tables()
        assert tbls.type is not RESPONSE_TYPE.ERROR

    def test_3_describe_table(self):
        described = self.handler.get_columns("home_rentals")
        assert described.type is RESPONSE_TYPE.TABLE

    def test_4_select_query(self):
        query = "SELECT * FROM home_rentals WHERE 'id'='3712'"
        result = self.handler.query(query)
        assert result.type is RESPONSE_TYPE.TABLE
