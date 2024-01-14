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


class TaskStatus:
    NOT_STARTED = 0
    IN_PROGRESS = 1
    COMPLETE = 2
    ERROR = 4


class TaskStatusDesc:
    NOT_STARTED = "Not Started"
    IN_PROGRESS = "In Progress"
    COMPLETE = "Complete"
    ERROR = "Error"


status_mapping = {
    TaskStatus.NOT_STARTED: TaskStatusDesc.NOT_STARTED,
    TaskStatus.IN_PROGRESS: TaskStatusDesc.IN_PROGRESS,
    TaskStatus.COMPLETE: TaskStatusDesc.COMPLETE,
    TaskStatus.ERROR: TaskStatusDesc.ERROR,
}
