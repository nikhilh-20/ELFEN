from django.test import TestCase


class ElfenHomeTestCase(TestCase):
    databases = {"elfen"}

    @classmethod
    def setUpTestData(cls):
        cls.elfen_home_url = "/web/"

    def test_get_elfen_home_page(self):
        """
        Access to ELFEN registration portal should be available without
        authentication.
        """
        response = self.client.get(self.elfen_home_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "web/home.html")

    def test_get_elfen_home_page_redirect(self):
        """
        On accessing "" URL, it should be redirected to self.elfen_home_url.
        """
        response = self.client.get("")
        self.assertRedirects(response, self.elfen_home_url)
