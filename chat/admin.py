from django.contrib import admin
from .models import *

admin.site.register(User)
admin.site.register(FriendRequest)
admin.site.register(Friendship)


