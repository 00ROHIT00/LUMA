from django.contrib import admin
from .models import User, Chat, Message, Report, Broadcast

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_active', 'is_admin')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    list_filter = ('is_active', 'is_admin')
    ordering = ('username',)
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'profile_picture')}),
        ('Permissions', {'fields': ('is_active', 'is_admin')}),
    )

class MessageInline(admin.TabularInline):
    model = Message
    extra = 0
    readonly_fields = ('sent_at',)

@admin.register(Chat)
class ChatAdmin(admin.ModelAdmin):
    list_display = ('id', 'sender', 'recipient', 'created_at', 'updated_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('sender__username', 'recipient__username')
    ordering = ('-updated_at',)
    inlines = [MessageInline]
    raw_id_fields = ('sender', 'recipient')

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'chat', 'sender', 'content', 'sent_at')
    list_filter = ('sent_at',)
    search_fields = ('content', 'sender__username')
    ordering = ('-sent_at',)
    raw_id_fields = ('chat', 'sender')

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'message', 'reporter', 'reported_at', 'status', 'reviewed_by')
    list_filter = ('reported_at', 'status')
    search_fields = ('message__content', 'reporter__username', 'reviewed_by__username')
    ordering = ('-reported_at',)
    raw_id_fields = ('message', 'reporter', 'reviewed_by')
    readonly_fields = ('reported_at',)
    fieldsets = (
        (None, {
            'fields': ('message', 'reporter', 'status')
        }),
        ('Review Information', {
            'fields': ('reviewed_by', 'reviewed_at', 'notes')
        })
    )

@admin.register(Broadcast)
class BroadcastAdmin(admin.ModelAdmin):
    list_display = ('id', 'admin', 'message', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('message', 'admin__username')
    ordering = ('-created_at',)
    raw_id_fields = ('admin',)
    readonly_fields = ('created_at',)
    fieldsets = (
        (None, {
            'fields': ('admin', 'message')
        }),
        ('Timestamp', {
            'fields': ('created_at',)
        })
    )
