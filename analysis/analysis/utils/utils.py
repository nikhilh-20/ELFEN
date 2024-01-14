"""
Copyright (C) 2023-2024 Nikhil Ashok Hegde (@ka1do9)

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


def update_object_fields(obj, field_values):
    """
    This function updates specified fields/attributes of an object with provided
    values.

    :param obj: Object to update
    :param field_values: Fields/attributes of an object with associates values
    :type field_values: list of tuples
    :return: None
    :rtype: None
    """

    for attribute, new_value in field_values:
        setattr(obj, attribute, new_value)
