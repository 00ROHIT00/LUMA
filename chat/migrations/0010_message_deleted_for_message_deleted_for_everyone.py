# Generated by Django 5.1.6 on 2025-03-16 17:26

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chat', '0009_message_read_by'),
    ]

    operations = [
        migrations.AddField(
            model_name='message',
            name='deleted_for',
            field=models.ManyToManyField(blank=True, related_name='deleted_messages', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='message',
            name='deleted_for_everyone',
            field=models.BooleanField(default=False),
        ),
    ]
