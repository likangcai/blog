#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @Author  : 影子
# @Time    : 2021-04-03 15:09
# @Software: PyCharm
# @File    : urls.py

# 进行users子应用的视图路由
from django.urls import path
from users.views import RegisterView

urlpatterns = [
    # path的第一个参数，路由
    # PATH的第二个参数，视图函数名
    path('register/', RegisterView.as_view(), name='register'),
]
