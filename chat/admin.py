from django.contrib import admin
from .models import User, Chat, Message, Report, Broadcast, Notification, BlockedUser, Payment

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
    list_display = ('id', 'chat', 'sender', 'content', 'sent_at', 'deleted_for_everyone')
    list_filter = ('sent_at', 'deleted_for_everyone')
    search_fields = ('content', 'sender__username', 'chat__sender__username', 'chat__recipient__username')
    ordering = ('-sent_at',)
    raw_id_fields = ('chat', 'sender')

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'reporter', 'message', 'reported_at', 'status', 'reviewed_by')
    list_filter = ('status', 'reported_at')
    search_fields = ('reporter__username', 'message__content')
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

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'type', 'message', 'created_at', 'read')
    list_filter = ('type', 'read', 'created_at')
    search_fields = ('message', 'user__username')
    ordering = ('-created_at',)
    raw_id_fields = ('user',)

@admin.register(BlockedUser)
class BlockedUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'blocker', 'blocked', 'blocked_at')
    list_filter = ('blocked_at',)
    search_fields = ('blocker__username', 'blocked__username')
    ordering = ('-blocked_at',)
    raw_id_fields = ('blocker', 'blocked')

@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'amount', 'currency', 'status', 'created_at')
    list_filter = ('status', 'currency', 'created_at')
    search_fields = ('user__username', 'razorpay_order_id', 'razorpay_payment_id')
    ordering = ('-created_at',)
    raw_id_fields = ('user',)
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        (None, {
            'fields': ('user', 'amount', 'currency', 'status')
        }),
        ('Payment Details', {
            'fields': ('razorpay_order_id', 'razorpay_payment_id', 'razorpay_signature')
        }),
        ('Additional Information', {
            'fields': ('notes',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        })
    )
