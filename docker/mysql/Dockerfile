#Copyright (C) 2023-2024 Nikhil Ashok Hegde (@ka1do9)
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <https://www.gnu.org/licenses/>.

FROM mysql:8

ENV MYSQL_ROOT_PASSWORD="mysqlsecretpwd"
ENV MYSQL_DATABASE="elfen_db"
ENV MYSQL_USER="elfen"
ENV MYSQL_PASSWORD="elfen"

COPY docker/mysql/init.sh /docker-entrypoint-initdb.d/
RUN chmod +x /docker-entrypoint-initdb.d/init.sh