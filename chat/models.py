from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

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
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)  # Optional field
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

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