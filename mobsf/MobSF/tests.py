from django.test import TestCase
from django.urls import reverse


class PageLanguageTests(TestCase):
    def test_login_page_defaults_to_english(self):
        response = self.client.get(reverse('login'))

        self.assertContains(response, 'Sign in to access')
        self.assertContains(response, 'STATIC ANALYZER')
        self.assertContains(response, '<select name="language"', html=False)
        self.assertContains(
            response,
            '<option value="en" selected>English</option>',
            html=True,
        )
        self.assertContains(
            response,
            '<option value="zh-hans">中文</option>',
            html=True,
        )

    def test_can_switch_to_simplified_chinese(self):
        self.client.post(
            reverse('set_language'),
            {'language': 'zh-hans', 'next': '/login/'},
        )

        response = self.client.get(reverse('login'))

        self.assertContains(response, '登录访问')
        self.assertContains(response, '静态分析')
        self.assertContains(
            response,
            '<option value="zh-hans" selected>中文</option>',
            html=True,
        )

    def test_can_switch_back_to_english(self):
        self.client.post(
            reverse('set_language'),
            {'language': 'zh-hans', 'next': '/login/'},
        )
        self.client.post(
            reverse('set_language'),
            {'language': 'en', 'next': '/login/'},
        )

        response = self.client.get(reverse('login'))

        self.assertContains(response, 'Sign in to access')
        self.assertContains(response, 'STATIC ANALYZER')
        self.assertContains(
            response,
            '<option value="en" selected>English</option>',
            html=True,
        )
