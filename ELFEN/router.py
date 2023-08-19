"""
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
"""


class ElfenRouter:
    """
    This is the only router. It routes accesses from Django apps like
    "admin", "auth", "contenttypes", "sessions" to the "default" database.
    It routes accesses from "web" and "analysis" apps to the "elfen" database.
    This is the primary database that stores ELFEN data.
    """
    DJANGO_BUILTIN_APPS = (
        "admin", "auth", "contenttypes", "sessions", "bootstrapsidebar"
    )
    ELFEN_APPS = ("web", "analysis")
    ELFEN_DB = "elfen"

    def db_for_read(self, model, **hints):
        """
        Data should be read from self.ELFEN_DB database for self.ELFEN_APPS.
        Returns "default" database for other apps' read actions.

        :param model: The name of the model
        :type model:  django.db.models.base.ModelBase
        :param hints: More kwargs that can be used to decide db read
                      eligibility.
        :type hints: dict
        :return: The name of the database to use for DB read actions.
        :rtype: str
        """
        if model._meta.app_label in self.ELFEN_APPS:
            return self.ELFEN_DB
        return "default"

    def db_for_write(self, model, **hints):
        """
        Data should be written to self.ELFEN_DB database for self.ELFEN_APPS.
        Returns "default" database for other apps' write actions.

        :param model: The name of the model
        :type model:  django.db.models.base.ModelBase
        :param hints: More kwargs that can be used to decide db write
                      eligibility.
        :type hints: dict
        :return: The name of the database to use for DB write actions.
        :rtype: str
        """
        if model._meta.app_label in self.ELFEN_APPS:
            return self.ELFEN_DB
        return "default"

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Migrate Django in-built apps and self.ELFEN_APPS to the relevant database.
        Return True only in those cases. Else, return False. DO NOT return None
        because any app/db not satisfying routing conditions will be dumped into
        the default db.

        NOTE: I spent some time to understand why `manage.py migrate` was only
        calling allow_migrate with "db == default". Turns out `migrate` operates
        on only one DB at a time. So, also have to run `migrate --database=elfen`

        :param db: Database ID (see settings.py DATABASES dict keys)
        :type db: str
        :param app_label: The name of the app
        :type app_label: str
        :param model_name: The name of the model
        :type model_name: str
        :param hints: More kwargs that can be used to decide migration
                      eligibility.
        :type hints: dict
        :return: Decision to migrate model to DB
        :rtype: bool
        """
        if app_label in self.ELFEN_APPS and db == self.ELFEN_DB:
            return True
        elif app_label in self.DJANGO_BUILTIN_APPS and db == "default":
            return True
        return False
