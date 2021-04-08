#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @Author  : 影子
# @Time    : 2021-04-08 17:43
# @Software: PyCharm
# @File    : urls.py

from django.urls import path
from home.views import IndexView

urlpatterns = [
    # 首页的路由
    path('', IndexView.as_view(), name='index'),
]
