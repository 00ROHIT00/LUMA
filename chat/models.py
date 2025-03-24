from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone
from django.db.models import Q

class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        if not username:
            raise ValueError("Username is required")

        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault("is_admin", True)
        extra_fields.setdefault("is_active", True)
        return self.create_user(username, email, password, **extra_fields)
        

class User(AbstractBaseUser):
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    username = models.CharField(max_length=30, unique=True)
    email = models.EmailField(unique=True)
    profile_picture = models.ImageField(upload_to='profile_pics', blank=True, null=True)  # Removed trailing slash
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_banned = models.BooleanField(default=False)
    ban_expiry = models.DateTimeField(null=True, blank=True)
    ban_reason = models.TextField(blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']

    class Meta:
        db_table = 'chat_user'

    def __str__(self):
        return self.username

    def delete(self, *args, **kwargs):
        try:
            # First, delete all messages where this user is the sender
            print(f"Deleting messages for user {self.username}")
            Message.objects.filter(sender=self).delete()
            
            # Then, delete all chats where this user is involved
            print(f"Deleting chats for user {self.username}")
            Chat.objects.filter(
                models.Q(sender=self) | models.Q(recipient=self)
            ).delete()
            
            # Finally, delete the user
            print(f"Deleting user {self.username}")
            super().delete(*args, **kwargs)
            print(f"Successfully deleted user {self.username}")
        except Exception as e:
            print(f"Error deleting user {self.username}: {str(e)}")
            raise

    @property
    def is_staff(self):
        return self.is_admin
    
    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return self.is_admin

    def ban_user(self, duration_days, reason=None):
        self.is_banned = True
        self.ban_expiry = timezone.now() + timezone.timedelta(days=duration_days)
        self.ban_reason = reason
        self.save()

    def unban_user(self):
        self.is_banned = False
        self.ban_expiry = None
        self.ban_reason = None
        self.save()

    def is_currently_banned(self):
        if not self.is_banned:
            return False
        if self.ban_expiry and timezone.now() > self.ban_expiry:
            self.unban_user()
            return False
        return True

    def get_ban_duration_remaining(self):
        if not self.is_banned or not self.ban_expiry:
            return None
        remaining = self.ban_expiry - timezone.now()
        if remaining.days < 0:
            self.unban_user()
            return None
        return remaining.days

class Chat(models.Model):
    sender = models.ForeignKey(User, related_name='sender_chats', on_delete=models.CASCADE)
    recipient = models.ForeignKey(User, related_name='recipient_chats', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Chat between {self.sender.username} and {self.recipient.username}"

    def delete(self, *args, **kwargs):
        try:
            # First delete all messages in this chat
            print(f"Deleting messages for chat {self.id}")
            self.messages.all().delete()
            
            # Then delete the chat itself
            print(f"Deleting chat {self.id}")
            super().delete(*args, **kwargs)
            print(f"Successfully deleted chat {self.id}")
        except Exception as e:
            print(f"Error deleting chat {self.id}: {str(e)}")
            raise

    class Meta:
        db_table = 'chat_chat'

class Message(models.Model):
    chat = models.ForeignKey(Chat, related_name='messages', on_delete=models.CASCADE)
    sender = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    sent_at = models.DateTimeField(auto_now_add=True)
    read_by = models.ManyToManyField(User, related_name='read_messages', blank=True)
    deleted_for = models.ManyToManyField(User, related_name='deleted_messages', blank=True)
    deleted_for_everyone = models.BooleanField(default=False)
    attachment = models.FileField(upload_to='chat_attachments', null=True, blank=True)  # Removed trailing slash
    attachment_type = models.CharField(max_length=50, null=True, blank=True)
    attachment_name = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return f"Message from {self.sender.username} at {self.sent_at}"

    def mark_as_read(self, user):
        self.read_by.add(user)
        self.save()

    def is_read_by(self, user):
        return self.read_by.filter(id=user.id).exists()

    def delete_for_user(self, user):
        self.deleted_for.add(user)
        self.save()

    def delete_for_everyone(self):
        self.deleted_for_everyone = True
        self.save()

    def is_deleted_for(self, user):
        return self.deleted_for.filter(id=user.id).exists()

    class Meta:
        db_table = 'chat_message'
        ordering = ['sent_at']

class Report(models.Model):
    REPORT_STATUSES = [
        ('pending', 'Pending Review'),
        ('reviewed', 'Reviewed'),
        ('resolved', 'Resolved'),
        ('dismissed', 'Dismissed'),
    ]

    message = models.ForeignKey(Message, related_name='reports', on_delete=models.CASCADE)
    reporter = models.ForeignKey(User, related_name='reported_messages', on_delete=models.CASCADE)
    reported_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=REPORT_STATUSES, default='pending')
    reviewed_by = models.ForeignKey(User, related_name='reviewed_reports', on_delete=models.SET_NULL, null=True, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Report by {self.reporter.username} on message {self.message.id}"

    class Meta:
        db_table = 'chat_report'
        ordering = ['-reported_at']

class Broadcast(models.Model):
    admin = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='broadcasts')
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Broadcast by {self.admin.username} at {self.created_at}"
    
    def send_to_all_users(self):
        """Create notifications for all users when a broadcast is sent"""
        print(f"Starting broadcast notification creation for broadcast ID: {self.id}")
        users = User.objects.filter(is_active=True).exclude(id=self.admin.id)
        print(f"Found {users.count()} active users to notify")
        
        notifications = []
        for user in users:
            print(f"Creating notification for user: {user.username}")
            notification = Notification(
                user=user,
                type='info',
                message=self.message,
                admin_notes=f"Broadcast sent by {self.admin.username}"
            )
            notifications.append(notification)
        
        created = Notification.objects.bulk_create(notifications)
        print(f"Successfully created {len(created)} notifications")
        return created
    
    class Meta:
        db_table = 'chat_broadcast'
        ordering = ['-created_at']

class Notification(models.Model):
    TYPES = (
        ('warning', 'Warning'),
        ('info', 'Information'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    type = models.CharField(max_length=10, choices=TYPES)
    message = models.TextField()
    admin_notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

class BlockedUser(models.Model):
    blocker = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blocked_users')
    blocked = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blocked_by')
    blocked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('blocker', 'blocked')
        ordering = ['-blocked_at']

    def __str__(self):
        return f"{self.blocker.username} blocked {self.blocked.username}"

    @classmethod
    def is_blocked(cls, user1, user2):
        """Check if user1 is blocked by user2 or vice versa"""
        return cls.objects.filter(
            (Q(blocker=user1, blocked=user2) | Q(blocker=user2, blocked=user1))
        ).exists()