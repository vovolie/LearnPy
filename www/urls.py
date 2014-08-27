#!/usr/bin/evn python
# -*- coding: utf-8 -*-

__author__ = 'vovo'

import os, re, time, base64, hashlib, logging

from transwarp.web import get, view, ctx, post, interceptor, seeother, notfound
from models import User, Blog, Comment

from apis import api, APIError, APIValueError, APIPermissionError, APIResourceNotFoundError

@view('blogs.html')
@get('/')
def index():
    blogs = Blog.find_all()
    user = User.find_first('where email=?', 'test@example.com')
    return dict(blogs=blogs, user=user)

@api
@get('/api/users')
def api_get_users():
    users = User.find_by('order by created_at desc')
    for u in users:
        u.password = '******'
    return dict(users=users)