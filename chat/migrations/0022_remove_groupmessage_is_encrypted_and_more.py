# Generated by Django 5.1.6 on 2025-03-29 16:23

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('chat', '0021_groupmessage_is_encrypted_message_is_encrypted'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='groupmessage',
            name='is_encrypted',
        ),
        migrations.RemoveField(
            model_name='message',
            name='is_encrypted',
        ),
    ]
