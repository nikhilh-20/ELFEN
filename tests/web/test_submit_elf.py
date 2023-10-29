from django.test import TestCase
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile


class SubmitElfTestCase(TestCase):
    databases = {"elfen", "default"}

    @classmethod
    def setUpTestData(cls):
        cls.submit_elf_url = "/web/submit/file"
        cls.submit_elf_template = "web/submit_elf.html"
        cls.submitted_elf_template = "web/report_file.html"
        cls.username = "testuser"
        cls.pwd = "1X<ISRUkw+tuK"

    def test_get_elfen_elf_submission_page_unauthenticated(self):
        """
        It should not be possible to access the ELF submission page without
        authentication.
        """
        response = self.client.get(self.submit_elf_url)
        self.assertRedirects(response, "/web/login/?next=/web/submit/file")

    def test_get_elfen_elf_submission_page_authenticated(self):
        """
        Access to the ELF submission page should be available after
        authentication.
        """
        test_user = User.objects.create_user(username=self.username,
                                             password=self.pwd)
        test_user.save()

        self.client.login(username=self.username, password=self.pwd)
        response = self.client.get(self.submit_elf_url)
        self.assertEqual(str(response.context['user']), self.username)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, self.submit_elf_template)

    def test_submit_elf_no_userland(self):
        """
        Check if ELF binary submission is successful through the submission
        portal form. No userland tracing. This test case does not monitor
        the outcome of the analysis.
        """
        test_user = User.objects.create_user(username=self.username,
                                             password=self.pwd)
        test_user.save()
        self.client.login(username=self.username, password=self.pwd)

        # Tiny ELF: http://timelessname.com/elfbin/helloworld.tar.gz
        content = b"\x7fELF\x01\x01\x01Hi World\n\x02\x00\x03\x00\x01\x00\x00" \
                  b"\x00\x80\x80\x04\x084\x00\x00\x00\x00\xb8\x04\x00\x00\x00" \
                  b"\xcd\x80\xebX \x00\x02\x00(\x00\x05\x00\x04\x00\x01\x00" \
                  b"\x00\x00\x00\x00\x00\x00\x00\x80\x04\x08\x00\x80\x04\x08" \
                  b"\xa2\x00\x00\x00\xa2\x00\x00\x00\x05\x00\x00\x00\x00\x10" \
                  b"\x00\x00\x01\x00\x00\x00\xa4\x00\x00\x00\xa4\x90\x04\x08" \
                  b"\xa4\x90\x04\x08\t\x00\x00\x00\t\x00\x00\x00\xba\t\x00" \
                  b"\x00\x00\xb9\x07\x90\x04\x08\xbb\x01\x00\x00\x00\xeb\xa4" \
                  b"\x00\x00\x00\xeb\xea\xbb\x00\x00\x00\x00\xb8\x01\x00\x00" \
                  b"\x00\xcd\x80"
        file_ = SimpleUploadedFile(name="hi_world.elf", content=content,
                                   content_type="application/x-executable")

        response = self.client.post(self.submit_elf_url, {"file": file_,
                                                          "userland_tracing": False,
                                                          "execution_time": 60},
                                    format='multipart')
        self.assertEqual(response.status_code, 302)

    def test_submit_elf_with_userland(self):
        """
        Check if ELF binary submission is successful through the submission
        portal form. Includes userland tracing. This test case does not monitor
        the outcome of the analysis.
        """
        test_user = User.objects.create_user(username=self.username,
                                             password=self.pwd)
        test_user.save()
        self.client.login(username=self.username, password=self.pwd)

        # Tiny ELF: http://timelessname.com/elfbin/helloworld.tar.gz
        content = b"\x7fELF\x01\x01\x01Hi World\n\x02\x00\x03\x00\x01\x00\x00" \
                  b"\x00\x80\x80\x04\x084\x00\x00\x00\x00\xb8\x04\x00\x00\x00" \
                  b"\xcd\x80\xebX \x00\x02\x00(\x00\x05\x00\x04\x00\x01\x00" \
                  b"\x00\x00\x00\x00\x00\x00\x00\x80\x04\x08\x00\x80\x04\x08" \
                  b"\xa2\x00\x00\x00\xa2\x00\x00\x00\x05\x00\x00\x00\x00\x10" \
                  b"\x00\x00\x01\x00\x00\x00\xa4\x00\x00\x00\xa4\x90\x04\x08" \
                  b"\xa4\x90\x04\x08\t\x00\x00\x00\t\x00\x00\x00\xba\t\x00" \
                  b"\x00\x00\xb9\x07\x90\x04\x08\xbb\x01\x00\x00\x00\xeb\xa4" \
                  b"\x00\x00\x00\xeb\xea\xbb\x00\x00\x00\x00\xb8\x01\x00\x00" \
                  b"\x00\xcd\x80"
        file_ = SimpleUploadedFile(name="hi_world.elf", content=content,
                                   content_type="application/x-executable")

        response = self.client.post(self.submit_elf_url, {"file": file_,
                                                          "userland_tracing": True,
                                                          "execution_time": 60},
                                    format='multipart')
        self.assertEqual(response.status_code, 302)

    def test_submit_elf_with_internet(self):
        """
        Check if ELF binary submission is successful through the submission
        portal form. Includes internet access. This test case does not monitor
        the outcome of the analysis.
        """
        test_user = User.objects.create_user(username=self.username,
                                             password=self.pwd)
        test_user.save()
        self.client.login(username=self.username, password=self.pwd)

        # Tiny ELF: http://timelessname.com/elfbin/helloworld.tar.gz
        content = b"\x7fELF\x01\x01\x01Hi World\n\x02\x00\x03\x00\x01\x00\x00" \
                  b"\x00\x80\x80\x04\x084\x00\x00\x00\x00\xb8\x04\x00\x00\x00" \
                  b"\xcd\x80\xebX \x00\x02\x00(\x00\x05\x00\x04\x00\x01\x00" \
                  b"\x00\x00\x00\x00\x00\x00\x00\x80\x04\x08\x00\x80\x04\x08" \
                  b"\xa2\x00\x00\x00\xa2\x00\x00\x00\x05\x00\x00\x00\x00\x10" \
                  b"\x00\x00\x01\x00\x00\x00\xa4\x00\x00\x00\xa4\x90\x04\x08" \
                  b"\xa4\x90\x04\x08\t\x00\x00\x00\t\x00\x00\x00\xba\t\x00" \
                  b"\x00\x00\xb9\x07\x90\x04\x08\xbb\x01\x00\x00\x00\xeb\xa4" \
                  b"\x00\x00\x00\xeb\xea\xbb\x00\x00\x00\x00\xb8\x01\x00\x00" \
                  b"\x00\xcd\x80"
        file_ = SimpleUploadedFile(name="hi_world.elf", content=content,
                                   content_type="application/x-executable")

        response = self.client.post(self.submit_elf_url, {"file": file_,
                                                          "enable_internet": True,
                                                          "execution_time": 60},
                                    format='multipart')
        self.assertEqual(response.status_code, 302)
