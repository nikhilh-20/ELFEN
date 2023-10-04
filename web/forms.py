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

from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm


EXECUTION_TIME = (
    (60, "60s"),
    (80, "80s"),
    (100, "100s")
)


class RegistrationForm(UserCreationForm):
    """
    User registration form
    """
    email = forms.EmailField(required=True, widget=forms.TextInput(attrs={"class": "form-control"}))
    username = forms.CharField(widget=forms.TextInput(attrs={"class": "form-control"}))
    password1 = forms.CharField(help_text="Your password should contain at least 8 characters.\n"
                                          "Your password shouldn't be too similar to your personal information.\n"
                                          "Your password shouldn't be a commonly used password.\n"
                                          "Your password shouldn't be entirely numeric.",
                                widget=forms.PasswordInput(attrs={"class": "form-control"}))
    password2 = forms.CharField(widget=forms.PasswordInput(attrs={"class": "form-control"}))

    class Meta:
        model = User
        fields = ["username", "email", "password1", "password2"]
        attrs = {
            "class": "form-control"
        }


class MultipleFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True


class MultipleFileField(forms.FileField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("widget", MultipleFileInput(
            attrs={"class": "form-control"}
        ))
        super().__init__(*args, **kwargs)

    def clean(self, data, initial=None):
        single_file_clean = super().clean
        if isinstance(data, (list, tuple)):
            result = [single_file_clean(d, initial) for d in data]
        else:
            result = single_file_clean(data, initial)
        return result


class FileSubmissionForm(forms.Form):
    """
    This form is the template for user's file submission page
    """
    file = forms.FileField(help_text="The main ELF binary to analyze",
                           widget=forms.FileInput(attrs={"class": "form-control"}))
    additional_files = MultipleFileField(help_text="Dependencies will be placed in the same"
                                                   " directory as the main sample",
                                         required=False)
    execution_time = forms.ChoiceField(choices=EXECUTION_TIME,
                                       label="Dynamic Execution Time",
                                       help_text="Number of seconds for which to perform"
                                                 " dynamic analysis",
                                       widget=forms.Select(attrs={"class": "form-control"}))
    execution_arguments = forms.CharField(max_length=512,
                                          required=False,
                                          help_text="Command-line arguments (max length: 512) that "
                                                    "will be provided to the main sample. ESXi-related "
                                                    "files exist in /vmfs/volumes",
                                          widget=forms.TextInput(attrs={"class": "form-control",
                                                                        "placeholder": "Execution Arguments"}))
    userland_tracing = forms.BooleanField(required=False,
                                          initial=True,
                                          help_text="Perform userland tracing",
                                          widget=forms.CheckboxInput(attrs={"class": "checkbox-inline"}))
    # make_sample_public = forms.BooleanField(required=False, initial=True,
    #                                        help_text="Make sample and its analysis public")
