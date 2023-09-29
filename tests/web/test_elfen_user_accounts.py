from django.test import TestCase
from django.contrib.auth.models import User


class ElfenUserAccountsTestCase(TestCase):
    databases = {"default", "elfen"}

    @classmethod
    def setUpTestData(cls):
        cls.elfen_home = "/web/"
        cls.elfen_login_url = "/web/login/"
        cls.elfen_registration_url = "/web/register/"
        cls.elfen_pwd_change_url = "/web/password_change/"
        cls.elfen_login_template = "registration/login.html"
        cls.elfen_registration_template = "registration/sign_up.html"
        cls.elfen_pwd_change_template = "registration/password_change_form.html"
        cls.elfen_pwd_done_url = "/web/password_change/done/"
        cls.user_email = "testuser@test.com"
        cls.username = "testuser"
        cls.pwd = "1X<ISRUkw+tuK"

    def test_get_elfen_login_page(self):
        """
        Access to the ELF login portal should be available without
        authentication.
        """
        response = self.client.get(self.elfen_login_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, self.elfen_login_template)

    def test_get_elfen_register_page(self):
        """
        Access to the ELF registration portal should be available without
        authentication.
        """
        response = self.client.get(self.elfen_registration_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, self.elfen_registration_template)

    def test_register_login(self):
        """
        Check if user registration works correctly. If registration is successful,
        the user should be redirected to the home page.
        """
        form_data = {
            "email": self.user_email,
            "username": self.username,
            "password1": self.pwd,
            "password2": self.pwd
        }
        response = self.client.post(self.elfen_registration_url, data=form_data)
        self.assertRedirects(response, self.elfen_home)

    def test_do_login(self):
        """
        Check if user login works.
        """
        test_user = User.objects.create_user(username=self.username,
                                             password=self.pwd)
        test_user.save()
        self.client.login(username=self.username, password=self.pwd)

    def test_do_logout(self):
        """
        Check if user logout works correctly.
        """
        test_user = User.objects.create_user(username=self.username,
                                             password=self.pwd)
        test_user.save()
        self.client.login(username=self.username, password=self.pwd)
        self.client.logout()

    def test_change_pwd_login(self):
        """
        Check if password change works correctly. If successful, the user should
        be redirected to the "password change done" page.
        """
        test_user = User.objects.create_user(username=self.username,
                                             password=self.pwd)
        test_user.save()
        self.client.login(username=self.username, password=self.pwd)

        form_data = {
            "old_password": self.pwd,
            "new_password1": "5X<sS$U5-stuK",
            "new_password2": "5X<sS$U5-stuK"
        }
        response = self.client.get(self.elfen_pwd_change_url)
        self.assertTemplateUsed(response, self.elfen_pwd_change_template)
        response = self.client.post(self.elfen_pwd_change_url, data=form_data)
        self.assertRedirects(response, self.elfen_pwd_done_url)
