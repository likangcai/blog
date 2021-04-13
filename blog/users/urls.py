#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @Author  : 影子
# @Time    : 2021-04-03 15:09
# @Software: PyCharm
# @File    : urls.py

# 进行users子应用的视图路由
from django.urls import path
from users.views import RegisterView, ImageCodeView
from users.views import SmsCodeView, LoginView

urlpatterns = [
    # path的第一个参数，路由
    # PATH的第二个参数，视图函数名
    path('register/', RegisterView.as_view(), name='register'),

    # 图片验证码的路由
    path('imagecode/', ImageCodeView.as_view(), name='imagecode'),

    # 短信验证码路由
    path('smscode/', SmsCodeView.as_view(), name='smscode'),

    # 登录路由
    path('login/', LoginView.as_view(), name='login'),
]
