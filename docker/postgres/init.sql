/*
Copyright (C) 2023  Nikhil Ashok Hegde (@ka1do9)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

CREATE USER elfen WITH PASSWORD 'elfen';
CREATE DATABASE "elfen_db";
ALTER DATABASE elfen_db OWNER to elfen;
ALTER ROLE elfen SET client_encoding to "utf8";
ALTER ROLE elfen SET default_transaction_isolation TO "read committed";
GRANT ALL PRIVILEGES ON DATABASE elfen_db TO elfen;
/* elfen needs this privilege to create the test DB for Django unit tests */
ALTER USER elfen CREATEDB;